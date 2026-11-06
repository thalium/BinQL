import idapro  # noqa: F401

import json
import os
import sys
import time
import traceback
from collections.abc import Callable
from datetime import date
from pathlib import Path

import ida_funcs
import ida_hexrays
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import idaapi
import idautils
import idc

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

from decompiler.ida.utils import (
    Context,
    get_func_kind,
    get_imported_eas,
    get_sanitize_function_name,
    is_ea_internal,
    is_function_internal,
    remove_double_underscore,
    sanitize_function_name,
)
from utils.logger import TrapLogger
from utils.trap import trap_generator_t

from .visitors import ctree_visitor_t, global_visitor_t


def crash_handler(exc_type, exc_value, exc_traceback) -> None:
    logger = TrapLogger.from_env()
    logger.error("=== Exception ===")

    tb = traceback.extract_tb(exc_traceback)

    for frame, line in zip(traceback.walk_tb(exc_traceback), tb, strict=True):
        frame_obj, _ = frame

        logger.error(f"\nFile: {line.filename}")
        logger.error(f"Function: {line.name}")
        logger.error(f"Line: {line.lineno}")

        logger.error("Locals:")
        for k, v in frame_obj.f_locals.items():
            try:
                logger.error(f"  {k} = {v!r}")
            except Exception:
                logger.error(f"  {k} = <unprintable>")

    logger.error(
        "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    )


_PROGRESS_INTERVAL = 2.0  # seconds between progress reports

_PROC_HEXRAYS_PRODUCT: dict[str, str] = {
    "metapc": "HEXX86",  # overridden to HEXX64 if is_64bit()
    "80386p": "HEXX86",
    "arm": "HEXARM",
    "armb": "HEXARM",
    "arm64": "HEXARM64",
    "mips": "HEXMIPS",
    "mipsb": "HEXMIPS",
    "mipsl": "HEXMIPS",
    "ppc": "HEXPPC",
    "ppcb": "HEXPPC",
    "ppc64": "HEXPPC",
    "riscv": "HEXRISCV",
}


def _required_product(proc: str) -> str | None:
    required = _PROC_HEXRAYS_PRODUCT.get(proc.lower())
    if (
        required
        and proc.lower() in ("metapc", "80386p")
        and bool(idc.get_inf_attr(idc.INF_LFLAGS) & 0x4)
    ):
        return "HEXX64"
    return required


def _check_hexrays_license(
    proc: str, license_path: str | None = None
) -> tuple[str | None, str | None]:
    """(error_msg, required_product) if the license lacks the arch's decompiler, else (None, None)."""
    required = _PROC_HEXRAYS_PRODUCT.get(proc.lower())
    if required is None:
        return None, None
    if proc.lower() in ("metapc", "80386p") and bool(
        idc.get_inf_attr(idc.INF_LFLAGS) & 0x4
    ):
        required = "HEXX64"

    ida_lic = license_path or os.environ.get("IDA_LICENSE", "")
    if ida_lic.startswith("keyfile="):
        license_path = ida_lic[len("keyfile=") :]
    elif ida_lic:
        license_path = ida_lic
    else:
        return (
            f"IDA_LICENSE is not set — arch '{proc}' requires a Hex-Rays {required} license. "
            f"Set IDA_LICENSE=<path-to-hexlic> pointing to a license file that includes {required}."
        ), required

    try:
        data = json.loads(Path(license_path).read_text())
    except Exception as e:
        return f"cannot read license file at {license_path}: {e}", required

    today = date.today().isoformat()
    covered: set[str] = {
        addon["code"]
        for lic in data.get("payload", {}).get("licenses", [])
        if lic.get("end_date", "") >= today
        for addon in lic.get("add_ons", [])
        if addon.get("end_date", "") >= today
    }
    if required not in covered:
        covered_str = ", ".join(sorted(covered)) or "none"
        return (
            f"license at {license_path} covers [{covered_str}], "
            f"missing {required} required for arch '{proc}'"
        ), required
    return None, None


class Analyse:
    def __init__(
        self,
        ctx: Context,
        report: Callable[[str], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
    ):
        self.ctx = ctx
        self.logger = TrapLogger.from_env()
        self.trap_generator = trap_generator_t(self.ctx)
        self._report = report or (lambda _: None)
        self._should_stop = should_stop or (lambda: False)
        self.license_product_hint: str | None = None
        self.stopped_early: bool = False

    def analyse_binary(self) -> None:
        """
        Phase 1: Perform binary-level analysis.
        Collect all known global names (non-function symbols and data labels) into `ctx.binary_globals` and emit a function row per function and extern, keyed by EA in `ctx.functions_trap`.
        """
        self.logger.info("[+] Analyzing binary...")

        # Source: https://github.com/mrexodia/ida-pro-mcp/commit/f0eaccaef82843959d553268f49b5bc8688f00f3
        # IDA normalises leading '__' to '_', so we apply remove_double_underscore.
        self.ctx.binary_globals = [
            remove_double_underscore(name)
            for ea, name in idautils.Names()
            if not idaapi.get_func(ea)
        ]

        num_functions = ida_funcs.get_func_qty()

        # Functions
        # Note: traversed through EA in ascending order
        t_last = time.monotonic()
        for func_idx, func_ea in enumerate(idautils.Functions()):
            if self._should_stop():
                self.stopped_early = True
                self._report(f"Phase 1 stopped early: {func_idx} / {num_functions}")
                break
            func = ida_funcs.get_func(func_ea)
            if func is None:
                self.logger.error(f"get_func returned None for ea={hex(func_ea)}")
                continue
            func_name = get_sanitize_function_name(func)
            func_decl = idaapi.print_type(
                func_ea, idaapi.PRTYPE_1LINE | idaapi.PRTYPE_SEMI
            )

            func_type = "internal" if is_function_internal(func) else "external"
            self.logger.info(
                f"Function n°{func_idx}/{num_functions} at 0x{func.start_ea:X}: {func_type} {func_name}"
            )

            func_tif = None
            if idaapi.IDA_SDK_VERSION == 900:
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, func.start_ea):
                    func_tif = tif
                else:
                    self.logger.warning(
                        f"Can't retrieve typeinfo of function {func_name} @{hex(func.start_ea)}"
                    )
            elif idaapi.IDA_SDK_VERSION >= 910:
                func_tif = func.prototype
            else:
                self.logger.warning(
                    f"Unsupported IDA SDK version {idaapi.IDA_SDK_VERSION}; func_tif will be None"
                )
            try:
                func_id = self.trap_generator.handler_function(
                    func_name, func_decl, func.start_ea, func.end_ea, func_tif
                )
            except Exception:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error(
                    f"FUNCTION_DROPPED (phase 1) {func_name} @ {hex(func.start_ea)}"
                )
                self.ctx.dropped_functions.append(func_name)
                crash_handler(exc_type, exc_value, exc_traceback)
                continue

            self.ctx.functions_trap[func.start_ea] = func_id
            self.trap_generator.flush()
            self.ctx.types_manager.flush()

            now = time.monotonic()
            if now - t_last >= _PROGRESS_INTERVAL:
                self._report(f"Phase 1: {func_idx + 1} / {num_functions}")
                t_last = now

        self._register_externals()
        self.logger.debug(f"functions_trap: {self.ctx.functions_trap}")

    def _register_externals(self) -> None:
        """Register imports with no `func_t` so calls to them resolve instead of
        dropping the call node."""
        eas: set[int] = set(get_imported_eas())
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg is not None and seg.type == ida_segment.SEG_XTRN:
                for ea in idautils.Heads(seg.start_ea, seg.end_ea):
                    if ida_name.get_ea_name(ea):
                        eas.add(ea)

        for ea in eas:
            if ea in self.ctx.functions_trap:
                continue
            name = sanitize_function_name(
                ida_name.get_ea_name(ea) or f"sub_{ea:X}", is_ea_internal(ea)
            )
            try:
                func_id = self.trap_generator.handler_function(name, "", ea, ea, None)
            except Exception:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error(f"FUNCTION_DROPPED (extern) {name} @ {hex(ea)}")
                self.ctx.dropped_functions.append(name)
                crash_handler(exc_type, exc_value, exc_traceback)
                continue
            self.ctx.functions_trap[ea] = func_id

    def analyse_function(self) -> None:
        """Phase 2: Perform per-function analysis.

        Decompile each function and run, in order:
        1. Type generation — emit param / lvar traps and their types.
        2. Global visitor — collect globals accessed in the body.
        3. C-tree visitor — emit statement / expression traps.

        Failures are logged and the function skipped, so one bad function
        doesn't abort the run.
        """
        self.logger.info("[+] Analyzing functions...")

        num_functions = ida_funcs.get_func_qty()
        imported_eas: set[int] = get_imported_eas()
        exported_eas: set[int] = {ea for _, _, ea, _ in idautils.Entries()}

        # Enumerate all functions by ascending EA:
        t_last = time.monotonic()
        for func_idx, func_ea in enumerate(idautils.Functions()):
            if self._should_stop():
                self.stopped_early = True
                self._report(f"Phase 2 stopped early: {func_idx} / {num_functions}")
                break
            func = ida_funcs.get_func(func_ea)
            if func is None:
                self.logger.error(f"get_func returned None for ea={hex(func_ea)}")
                continue
            func_name = get_sanitize_function_name(func)
            func_type = "internal" if is_function_internal(func) else "external"
            func_kind = get_func_kind(func, imported_eas, exported_eas)

            self.ctx.curr_fn_name = func_name
            self.ctx.lscopevars_trap.clear()
            self.ctx.label_trap.clear()
            self.ctx.gvars.clear()

            self.logger.info(
                f"Function n°{func_idx}/{num_functions} at 0x{func.start_ea:X}: {func_type} {func_name}"
            )

            # Decompile the current function:
            try:
                cfunc = ida_hexrays.decompile(func)
                if cfunc is None:
                    if not (func_kind == "imported" and func_type == "external"):
                        # Routine for thunks / tail-call stubs.
                        self.logger.debug(
                            f"Can't decompile {func_kind} {func_type} {func_name}"
                        )
                    continue
            except ida_hexrays.DecompilationFailure as exc:
                # ... may fail on external functions:
                if hasattr(exc, "hf") and "license" in exc.hf.desc().lower():
                    self.logger.error(
                        f"License error decompiling {func_name}: {exc.hf.desc()}"
                    )
                else:
                    self.logger.error(
                        f"Fail to decompile {func_kind} {func_type} Function n°{func_idx} {func_name}"
                    )
                continue

            self.ctx.cfunc = cfunc

            if func_ea not in self.ctx.functions_trap:
                self.logger.error(
                    f"{func_name} (ea={hex(func_ea)}) missing from functions_trap "
                    "(phase 1 raised while processing this function) — skipping function body"
                )
                continue

            self.logger.info(
                "\n".join(
                    [
                        f"C-Tree: Function n°{func_idx}/{num_functions}, {func_name} @ {hex(func_ea)}\n"
                    ]
                )
            )

            # 1. Type generation: map each local variable / parameter to its trap id:
            for lvar in filter(lambda lvar: lvar.name, cfunc.get_lvars()):
                try:
                    if func_ea in self.ctx.functions_trap:
                        lvar_id = None
                        if lvar.is_arg_var:
                            lvar_id = self.trap_generator.handler_param(
                                func_ea, func_name, lvar
                            )
                        else:
                            lvar_id = self.trap_generator.handler_lvar(
                                func_ea, func_name, lvar
                            )

                        # Add to local scope variables = parameters + lvars
                        self.ctx.lscopevars_trap[lvar.name] = lvar_id
                    else:
                        self.logger.error(
                            f"{lvar} not found in functions_trap for {func_name} (ea={hex(func_ea)})"
                        )
                except Exception:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    self.logger.error(
                        f"LVAR_DROPPED {func_name} @ {hex(func_ea)} lvar={lvar.name!r}"
                    )
                    crash_handler(exc_type, exc_value, exc_traceback)

            # 2. Global visitor: collect global variables accessed in this function:
            #
            # The list will be used in-situs in `ctree_visitor_t` to generate:
            # - Variable, on first use
            # - VariableAccess, on each use
            global_visitor = global_visitor_t(self.ctx)
            global_visitor.apply_to(cfunc.body, None)

            now = time.monotonic()
            if now - t_last >= _PROGRESS_INTERVAL:
                self._report(f"Phase 2: {func_idx + 1} / {num_functions}")
                t_last = now

            # 3. C-tree visitor: emit statement / expression traps.
            # Link the function to its c-tree root first (see "blocks" binary.dbscheme)
            func_trap = self.ctx.functions_trap.get(func_ea)
            trap = f"function_bodys({func_trap}, {self.ctx.global_id + 1})"
            self.trap_generator.write_trap("functions", trap)
            self.logger.trap(trap + "\n")

            try:
                # Apply the C-tree visitor to each function
                ctree_visitor = ctree_visitor_t(self.ctx, func_name)
                ctree_visitor.apply_to(cfunc.body, None)
                ctree_visitor.flush()

            except Exception:
                exc_type, exc_value, exc_traceback = sys.exc_info()

                # A handler raised despite the per-node guard in
                # ctree_visitor_t._guarded (e.g. apply_to itself, or flush).
                # Every trap buffered for this function is now discarded.
                self.logger.error(
                    f"FUNCTION_DROPPED (phase 2) {func_name} @ {hex(func_ea)}"
                )
                self.ctx.dropped_functions.append(func_name)

                # Log detailed crash info
                crash_handler(exc_type, exc_value, exc_traceback)

                # Continue with next function
                continue

            self.trap_generator.flush()
            self.ctx.types_manager.flush()

        dropped = self.ctx.dropped_functions
        if dropped or self.ctx.dropped_nodes:
            self.logger.error(
                f"EXTRACTION_HEALTH: {len(dropped)} function(s) dropped, "
                f"{self.ctx.dropped_nodes} node(s) skipped. "
                f"Dropped functions: {', '.join(dropped) if dropped else '(none)'}"
            )
        else:
            self.logger.info("EXTRACTION_HEALTH: no functions or nodes dropped")
