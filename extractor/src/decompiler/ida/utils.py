import math
import os
import re
import sys
from decimal import Decimal
from typing import TYPE_CHECKING

import ida_funcs
import ida_hexrays
import ida_name
import ida_segment
import ida_typeinf
import idaapi

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

if TYPE_CHECKING:
    from decompiler.ida.types import TypesManager


def reinterpret_raw_value(value: int, tif: ida_typeinf.tinfo_t | None) -> int:
    """Reinterpret IDA's raw uint64-container value per `tif`'s real width/sign.

    Falls back to 64-bit signed when `tif` is None or its size isn't 1/2/4/8 (e.g. void).
    """
    size = tif.get_size() if tif is not None else None
    if tif is None or size not in (1, 2, 4, 8):
        size, unsigned = 8, False
    else:
        unsigned = tif.is_unsigned()

    bits = size * 8
    value &= (1 << bits) - 1
    if unsigned:
        return value
    sign_bit = 1 << (bits - 1)
    return value - (1 << bits) if value & sign_bit else value


def trap_escape(value: object) -> str:
    """Escape a value for a double-quoted TRAP field by doubling `"`.

    The TRAP reader's only escape is `""` (no backslash processing, per
    `TRAPReader.unescape`); JSON-style `\\"` would close the field early and the
    rejected line drops the whole function via `analysis.analyse_function`'s `except`.
    """
    text = value if isinstance(value, str) else str(value)
    return text.replace('"', '""')


def format_trap_number(value: float) -> str:
    """Format a finite float as an exponent-free decimal for a TRAP `float` column.

    Raises ValueError on inf/nan: TRAP has no spelling for them.
    """
    fvalue = float(value)
    if not math.isfinite(fvalue):
        raise ValueError(f"non-finite value has no TRAP representation: {value!r}")
    text = repr(fvalue)
    if "e" in text or "E" in text:
        text = format(Decimal(text), "f")
    return text


def LINE():
    """Return the caller's line number."""
    return sys._getframe(1).f_lineno


def get_imported_eas() -> set[int]:
    imported: set[int] = set()

    def _cb(ea: int, name: str, ordinal: int) -> bool:
        imported.add(ea)
        return True

    for i in range(idaapi.get_import_module_qty()):
        if idaapi.get_import_module_name(i):
            idaapi.enum_import_names(i, _cb)

    return imported


def get_func_kind(
    func: ida_funcs.func_t, imported_eas: set[int], exported_eas: set[int]
) -> str:
    if func.start_ea in imported_eas:
        return "imported"
    if func.start_ea in exported_eas:
        return "exported"
    return "normal"


def is_ea_internal(ea: int) -> bool:
    """True unless `ea` is in the `extern` pseudo-segment (import stub, no c-tree)."""
    seg = ida_segment.getseg(ea)
    return seg is None or seg.type != ida_segment.SEG_XTRN


def is_function_internal(func: ida_funcs.func_t) -> bool:
    return is_ea_internal(func.start_ea)


def get_sanitize_function_name(func: ida_funcs.func_t | int) -> str:
    if isinstance(func, int):
        resolved = ida_funcs.get_func(func)
        assert resolved is not None
        func = resolved
    if is_function_internal(func):
        return sanitize_function_name(ida_name.get_ea_name(func.start_ea), True)
    return sanitize_function_name(ida_name.get_ea_name(func.start_ea), False)


def remove_double_underscore(source: str) -> str:
    underscore_pattern = re.compile(r"^__([a-zA-Z0-9_]+)$")
    match = underscore_pattern.match(source)
    if match:
        return "_" + match.group(1)
    return source


def sanitize_function_name(function_name: str, is_internal: bool) -> str:
    def remove_dot_double_underscore(s: str) -> str:
        """Map ".__<ident>" to "__<ident>"; else return `s` unchanged."""
        pattern = re.compile(r"^\.(__(?:[a-zA-Z0-9_]+))$")
        match = pattern.match(s)
        if match:
            return match.group(1)
        return s

    def remove_dot_single_underscore(s: str) -> str:
        """Map ".<ident>" (not ".__...") to "<ident>"; else return `s` unchanged."""
        pattern = re.compile(r"^\.(?!__)([a-zA-Z0-9_]+)$")
        match = pattern.match(s)
        if match:
            return match.group(1)
        return s

    function_name = remove_dot_double_underscore(function_name)
    function_name = remove_dot_single_underscore(function_name)
    if not is_internal:
        return "".join(["ext_", function_name])
    return function_name


def citem_t_display(citem: ida_hexrays.citem_t) -> None:
    """Print a citem's `dstr()` (debug helper)."""
    if citem.is_expr():
        print(citem.cexpr.dstr())  # noqa: T201
    else:
        print(citem.cinsn.dstr())  # noqa: T201


def get_citem_uuid(citem: ida_hexrays.citem_t) -> str:
    ret = str(hex(citem.ea)) + "-"
    if citem.is_expr():
        ret += citem.cexpr.dstr()
    else:
        ret += citem.cinsn.dstr()
    return ret


class Context:
    def __init__(
        self: "Context",
        global_id: int,
        func_name: str,
        cfunc: ida_hexrays.cfunc_t,
        functions_trap: dict[int, int],
        label_trap: dict[int, int],
        binary_globals: list[str],
        gvars: set[str],
        gvars_trap: dict[str, int],
        lvars_trap: dict[str, int],
        types_manager: "TypesManager",
    ):
        # Avoid circular imports
        from decompiler.ida.types import TypesManager

        self.global_id: int = global_id
        self.curr_fn_name = func_name
        self.cfunc = cfunc
        # EA -> trap id. An IDA function's identity is its start EA, never its name
        # (one func_t is reachable under many name spellings).
        self.functions_trap = functions_trap
        # str -> trap id for call targets that are not IDA functions
        # (helpers, intrinsics, indirect-call expressions).
        self.synthetic_trap: dict[str, int] = {}
        self.label_trap = label_trap
        self.binary_globals = binary_globals
        self.gvars = gvars
        self.gvars_trap = gvars_trap
        self.lscopevars_trap = lvars_trap
        self.trap_seen_kinds: set[str] = set()
        self.types_manager = TypesManager(self)

        # Extraction-health accounting
        self.dropped_functions: list[str] = []
        self.dropped_nodes: int = 0

    def increment_global_id(self) -> int:
        current = self.global_id
        self.global_id += 1
        return current


cot_generic_cases = [
    "cot_empty",
    "cot_comma",
    "cot_asg",
    "cot_asgbor",
    "cot_asgxor",
    "cot_asgband",
    "cot_asgadd",
    "cot_asgsub",
    "cot_asgmul",
    "cot_asgsshr",
    "cot_asgushr",
    "cot_asgshl",
    "cot_asgsdiv",
    "cot_asgudiv",
    "cot_asgsmod",
    "cot_asgumod",
    "cot_tern",
    "cot_lor",
    "cot_land",
    "cot_bor",
    "cot_xor",
    "cot_band",
    "cot_eq",
    "cot_ne",
    "cot_sge",
    "cot_uge",
    "cot_sle",
    "cot_ule",
    "cot_sgt",
    "cot_ugt",
    "cot_slt",
    "cot_ult",
    "cot_sshr",
    "cot_ushr",
    "cot_shl",
    "cot_add",
    "cot_sub",
    "cot_mul",
    "cot_sdiv",
    "cot_udiv",
    "cot_smod",
    "cot_umod",
    "cot_fadd",
    "cot_fsub",
    "cot_fmul",
    "cot_fdiv",
    "cot_lnot",
    "cot_bnot",
    "cot_neg",
    "cot_fneg",
    "cot_ref",
    "cot_postinc",
    "cot_postdec",
    "cot_preinc",
    "cot_predec",
    "cot_idx",
    "cot_insn",
]


cit_generic_cases = [
    "cit_empty",
    "cit_if",
    "cit_for",
    "cit_while",
    "cit_do",
    "cit_break",
    "cit_continue",
    "cit_return",
]

ida_builtin_basic_types = (
    # 0x0
    ida_typeinf.BT_UNK,
    # 0x30
    ida_typeinf.BTF_UNK,
    # 0x1
    ida_typeinf.BT_VOID,
    # 0x8
    ida_typeinf.BT_BOOL,
    # 0x20
    ida_typeinf.BTE_CHAR,
    # 0x32
    ida_typeinf.BTF_CHAR,
    # 0x7 = BTF_INT
    ida_typeinf.BT_INT,
    # 0x27
    ida_typeinf.BTF_UINT,
    # 0x12
    ida_typeinf.BTF_INT8,
    # 0x22
    ida_typeinf.BTF_UINT8,
    # 0x13
    ida_typeinf.BTF_INT16,
    # 0x23
    ida_typeinf.BTF_UINT16,
    # 0x14
    ida_typeinf.BTF_INT32,
    # 0x24
    ida_typeinf.BTF_UINT32,
    # 0x5
    ida_typeinf.BT_INT64,
    # 0x15
    ida_typeinf.BTF_INT64,
    # 0x25
    ida_typeinf.BTF_UINT64,
    # 0x16
    ida_typeinf.BTF_INT128,
    # 0x26
    ida_typeinf.BTF_UINT128,
    # 0x9
    ida_typeinf.BT_FLOAT,
    # 0x19
    ida_typeinf.BTF_DOUBLE,
    # 0x29
    ida_typeinf.BTF_LDOUBLE,
)
