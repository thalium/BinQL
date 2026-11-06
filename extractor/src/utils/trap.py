import hashlib
import os
import sys

import ida_hexrays
import ida_typeinf

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

from decompiler.ida.utils import Context, trap_escape
from utils.logger import TrapLogger


class trap_generator_t:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        binql_target = os.environ.get("BINQL_TARGET")
        if binql_target is None:
            raise RuntimeError("BINQL_TARGET environment variable is not set")
        self.binary_name = os.path.basename(binql_target)
        self.logger = TrapLogger.from_env()

        trap_dir = os.environ.get("CODEQL_EXTRACTOR_BINARY_TRAP_DIR")
        if trap_dir is None:
            raise RuntimeError("CODEQL_EXTRACTOR_BINARY_TRAP_DIR is not set")
        self._trap_dir = trap_dir
        self._buffer: dict[str, list[str]] = {}

    def _make_filename(self, kind: str) -> str:
        max_filename = 255 - len(".trap")
        if len(kind) >= max_filename:
            return hashlib.sha256(kind.encode("utf-8")).hexdigest()
        return kind

    def write_trap(self, kind: str, trap: str) -> None:
        filename = self._make_filename(kind)
        if filename not in self._buffer:
            lines: list[str] = []
            if filename not in self.ctx.trap_seen_kinds:
                lines.append('#comment=@"' + kind + '"')
            self._buffer[filename] = lines
        self._buffer[filename].append(trap)

    def flush(self) -> None:
        for filename, lines in self._buffer.items():
            trap_file = os.path.join(self._trap_dir, filename + ".trap")
            try:
                with open(trap_file, "a") as f:
                    f.write("\n".join(lines) + "\n")
                self.ctx.trap_seen_kinds.add(filename)
            except OSError as exc:
                self.logger.error(f"Failed to write trap to {trap_file}: {exc}")
        self._buffer.clear()

    def generate_location(self, kind: str, binary: str, start: int, end: int) -> int:
        location_id = self.ctx.increment_global_id()
        trap = f'locations({location_id}, "{binary}", {float(start)}, {float(end)})'
        trap_hex = f'locations({location_id}, "{binary}", {hex(start)}, {hex(end)})'
        self.write_trap(kind, trap)
        self.logger.trap(trap_hex + "\n")
        return location_id

        # Generics

    def handler_function(
        self,
        func_name,
        func_decl,
        func_start,
        func_end,
        func_tinfo: ida_typeinf.tinfo_t | None = None,
    ) -> int:
        def generate_function(
            func_name, func_decl, loc, func_tinfo: ida_typeinf.tinfo_t | None = None
        ) -> int:
            function_id = self.ctx.increment_global_id()

            if func_tinfo:
                function_type = self.ctx.types_manager.write_type(func_tinfo)
                trap = f'functions({function_id}, "{trap_escape(func_name)}", {function_type}, {loc})'
            else:
                trap = (
                    f'functions({function_id}, "{trap_escape(func_name)}", -1, {loc})'
                )

            self.write_trap("functions", trap)
            self.logger.trap(trap + "\n")
            return function_id

        loc_id = self.generate_location(
            "functions", self.binary_name, func_start, func_end
        )
        func_id = generate_function(func_name, func_decl, loc_id, func_tinfo)
        return func_id

    def handler_lvar(
        self, func_ea: int, func_name: str, lvar: ida_hexrays.lvars_t
    ) -> int:
        def generate_lvar(
            func_name: str, lvar_name: str, lvar_type: ida_typeinf.tinfo_t
        ) -> int:
            lvar_id = self.ctx.increment_global_id()
            func_id = self.ctx.functions_trap[func_ea]
            lvar_type_trap = self.ctx.types_manager.write_type(lvar_type)

            trap = f'lvars({lvar_id}, {func_id}, "{trap_escape(lvar_name)}", {str(bool(0)).lower()}, {lvar_type_trap})'

            self.write_trap(func_name, trap)
            self.logger.trap(trap + "\n")
            return lvar_id

        return generate_lvar(func_name, lvar.name, lvar.tif)

    def handler_param(self, func_ea: int, func_name: str, param: ida_hexrays.lvars_t):
        def generate_lvar(
            func_name: str, param_name: str, param_type: ida_typeinf.tinfo_t
        ):
            param_id = self.ctx.increment_global_id()
            func_id = self.ctx.functions_trap[func_ea]
            param_type_trap = self.ctx.types_manager.write_type(param_type)
            trap = f'lvars({param_id}, {func_id}, "{trap_escape(param_name)}", {str(bool(1)).lower()}, {param_type_trap})'
            self.write_trap(func_name, trap)
            self.logger.trap(trap + "\n")
            return param_id

        return generate_lvar(func_name, param.name, param.tif)

    def handler_gvar(
        self, func_name: str, lvar_name: str, gvar_type: ida_hexrays.lvars_t
    ):
        def generate_gvar(func_name, gvar_name, gvar_type: ida_hexrays.lvars_t):
            gvar_id = self.ctx.increment_global_id()
            gvar_type_trap = self.ctx.types_manager.write_type(gvar_type)
            trap = f'gvars({gvar_id}, "{trap_escape(gvar_name)}", {gvar_type_trap})'
            self.write_trap(func_name, trap)
            self.logger.trap(trap + "\n")
            return gvar_id

        return generate_gvar(func_name, lvar_name, gvar_type)

    def handler_gvar_acc(self, where: str, stmt: int, var: int):
        def generate_gvar_acc(where: str, stmt: int, var: int):
            trap = f"gvar_accs({stmt}, {var})"
            trap_hex = f"gvar_accs({stmt}, {var})"
            self.write_trap(where, trap)
            self.logger.trap(trap_hex + "\n")
            return id

        return generate_gvar_acc(where, stmt, var)

    def handler_lvar_acc(self, where: str, stmt: int, var: int):
        def generate_lvar_acc(where: str, stmt: int, var: int):
            trap = f"lvar_accs({stmt}, {var})"
            trap_hex = f"lvar_accs({stmt}, {var})"
            self.write_trap(where, trap)
            self.logger.trap(trap_hex + "\n")
            return id

        return generate_lvar_acc(where, stmt, var)

    def generate_var_acc(self, where: str, stmt: int, target: int):
        trap = f"var_accs({stmt}, {target})"
        trap_hex = f"var_accs({stmt}, {target})"
        self.write_trap(where, trap)
        self.logger.trap(trap_hex + "\n")
        return stmt
