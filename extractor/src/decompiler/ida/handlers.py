import ctypes
import math
import os
import re
import sys
from typing import TYPE_CHECKING

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ieee
import ida_lines
import ida_nalt
import ida_name
import ida_pro
import ida_typeinf
import ida_ua
import idaapi

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

from decompiler.ida.utils import (
    Context,
    format_trap_number,
    is_ea_internal,
    reinterpret_raw_value,
    sanitize_function_name,
    trap_escape,
)
from utils.constants import BADADDR_IDA, BADADDR_TRAP, cot_and_cit
from utils.logger import TrapLogger

if TYPE_CHECKING:
    from decompiler.ida.visitors import trap_generator_visitor_t


class handler_dispatcher_t:
    """Maps each Hex-Rays ctree opcode to its trap-emitting handler; one per visitor."""

    def __init__(
        self, ctx: Context, visitor_trap_generator: "trap_generator_visitor_t"
    ):
        self.ctx: Context = ctx
        self.visitor = visitor_trap_generator

        self.logger: TrapLogger = TrapLogger.from_env()

    # ctype_t handlers

    # cot_

    def cot_cast(self, e: ida_hexrays.cexpr_t):
        """Type cast `(T)expr`."""

        def generate_cast(stmt: int, expression: str) -> None:
            trap = f'castexprs({stmt}, "{trap_escape(expression)}")'
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap + "\n")

        loc_id = self.visitor.generate_location(self.visitor.binary_name, e)
        stmt_id = self.visitor.generate_node(loc_id, e)
        self.visitor.generate_edge(e)
        generate_cast(stmt_id, e.type)

    def cot_ptr(self, e: ida_hexrays.cexpr_t):
        """Pointer dereference (`*x`)."""

        def generate_ptr(stmt: int, expression: str) -> None:
            trap = f'pointerdereferenceexprs({stmt}, "{trap_escape(expression)}")'
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap + "\n")

        loc_id = self.visitor.generate_location(self.visitor.binary_name, e)
        stmt_id = self.visitor.generate_node(loc_id, e)
        self.visitor.generate_edge(e)
        generate_ptr(stmt_id, e.type)

    def _ensure_func_ea(self, ea: int) -> int:
        """Trap id for a real/extern IDA function, by start EA; created if missing."""
        func_id = self.ctx.functions_trap.get(ea)
        if func_id is None:
            name = sanitize_function_name(
                ida_name.get_ea_name(ea) or f"sub_{ea:X}", is_ea_internal(ea)
            )
            func_id = self.visitor.trap_generator.handler_function(name, "", ea, ea)
            self.ctx.functions_trap[ea] = func_id
        return func_id

    def _ensure_synthetic(self, key: str, f_decl, f_tinfo=None) -> int:
        """Trap id for a non-IDA-function call target (helper, intrinsic, indirect).

        String-keyed: no func_t/EA, so it can't duplicate a real function.
        """
        sid = self.ctx.synthetic_trap.get(key)
        if sid is None:
            sid = self.visitor.trap_generator.handler_function(
                key, f_decl, BADADDR_TRAP, BADADDR_TRAP, f_tinfo
            )
            self.ctx.synthetic_trap[key] = sid
        return sid

    def _handle_member_call(
        self,
        e: ida_hexrays.cexpr_t,
        stmt_id: int,
        generate_call,
        *,
        is_ptr: bool,
    ) -> None:
        full = e.x.dstr()
        prefix = e.x.x.dstr()
        sep = "->" if is_ptr else "."
        member_name = full.removeprefix(prefix).lstrip(sep)

        base_tinfo = e.x.x.type
        if is_ptr:
            if base_tinfo.is_ptr():
                base_tinfo = self.ctx.types_manager.strip_type(
                    base_tinfo.get_pointed_object()
                )
            base_name = base_tinfo.dstr().replace("struct ", "")
        else:
            base_name = self.ctx.types_manager.strip_type(base_tinfo).dstr()

        func_name = f"{base_name}-{member_name}"
        generate_call(
            stmt_id, self._ensure_synthetic(func_name, "DECL", e.x.type), isrealfn=0
        )

    def cot_call(self, e: ida_hexrays.cexpr_t):
        """Function call; resolves the target from the kind of `e.x` sub-expression."""

        def generate_call(stmt: int, target: int, isrealfn: int) -> None:
            trap = f"function_calls({stmt}, {target}, {str(bool(isrealfn)).lower()})"
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap + "\n")

        loc_id = self.visitor.generate_location(self.visitor.binary_name, e)
        stmt_id = self.visitor.generate_node(loc_id, e)
        self.visitor.generate_edge(e)

        match cot_and_cit[e.x.op]:
            case "cot_helper":
                # cot_helper is informing about the call's target, an intrinsic function
                generate_call(stmt_id, self._ensure_synthetic(e.x.helper, e.x.type), 0)
            case "cot_memref":
                self._handle_member_call(e, stmt_id, generate_call, is_ptr=False)

            case "cot_memptr":
                self._handle_member_call(e, stmt_id, generate_call, is_ptr=True)

            case "cot_obj":
                # cot_obj carries the call target: a real/extern function (has
                # an address) or a dynamic target (no resolvable address).
                if e.x.ea == BADADDR_IDA:
                    ea = e.x.obj_ea
                    func = ida_funcs.get_func(ea)
                    canon = func.start_ea if func is not None else ea
                    if canon != BADADDR_IDA and (
                        func is not None or ida_name.get_ea_name(ea)
                    ):
                        generate_call(stmt_id, self._ensure_func_ea(canon), 1)
                    else:
                        key = ida_pro.str2user(ida_lines.tag_remove(e.x.print1(None)))
                        generate_call(
                            stmt_id, self._ensure_synthetic(key, "DECL", e.x.type), 0
                        )
                else:
                    # cot_obj is not related to the call
                    self.logger.error("cot_call not related to the call")
            case "cot_ptr":
                pattern = r"([\*]+(?:\(.*?\)|[^\s()]+)?)(\(?.*\)?)$"
                # Group 1: leading derefs + first (...) or bare operand; group 2: the rest.
                #   **(int (__fastcall ***)(int))a1  -> "**(int (__fastcall ***)" + "(int))a1"
                #   **v7                             -> "**v7" + ""
                match = re.match(pattern, e.x.dstr())
                if not match:
                    self.logger.debug(f"e.x.dstr() {e.x.dstr()}")
                    self.logger.error(
                        "handler_cot_call: citem_t of type cot_ptr, regex failed"
                    )
                    return
                key = match.group(1) + match.group(2)
                generate_call(stmt_id, self._ensure_synthetic(key, match.group(2)), 0)
            case "cot_var" | "cot_cast" | "cot_idx" | "cot_call":
                # Indirect call through an expression: funcptr(args), ((type)e)(args),
                # table[n](args), get_handler()(args). Keyed by the printed expression.
                # get_handler()(args) form seen in ntoskrnl.exe 22631.7517 @ 0x140A80232 (MK_FP).
                # Available here: https://msdl.microsoft.com/download/symbols/ntoskrnl.exe/8E488D651047000/ntoskrnl.exe
                generate_call(
                    stmt_id, self._ensure_synthetic(e.x.dstr(), "DECL"), isrealfn=0
                )
            case _:
                self.logger.error(
                    f"handler_cot_call: not handled citem_t of type {cot_and_cit[e.x.op]}"
                )
                self.logger.debug(f"e.x.op       {cot_and_cit[e.x.op]}")
                self.logger.debug(f"e.x.refwidth {e.x.refwidth}")
                self.logger.debug(f"e.x.ea       {hex(e.x.ea)}")
        return

    def cot_memref(self, e: ida_hexrays.cexpr_t):
        """Struct/union member access by value (`x.m`); returns the node id."""
        loc_id = self.visitor.generate_location(self.visitor.binary_name, e)
        stmt_id = self.visitor.generate_node(loc_id, e, 59)
        self.visitor.generate_edge(e)

        struct_tinfo = self.ctx.types_manager.strip_type(e.x.type)

        if str(struct_tinfo) not in self.ctx.types_manager.types_trap:
            self.ctx.types_manager.write_type(struct_tinfo)

        udt_data = ida_typeinf.udt_type_data_t()
        if not struct_tinfo.get_udt_details(udt_data):
            self.logger.error(
                f"Failed to get UDT details: type={struct_tinfo.dstr()}, expr={e}"
            )
            return stmt_id

        target_offset = e.m * 8

        for member in udt_data:
            if member.offset == target_offset:
                field_identifier = f"{struct_tinfo!s}-{member.name}"

                if struct_tinfo.is_union():
                    if field_identifier not in self.ctx.types_manager.types_trap:
                        self.logger.error(
                            f"cot_memref to a member `{member.name}` of the union `{struct_tinfo.dstr()}`, is unknown"
                        )
                        return stmt_id
                    field_id = self.ctx.types_manager.types_trap[field_identifier]
                elif struct_tinfo.is_struct():
                    if field_identifier not in self.ctx.types_manager.types_trap:
                        self.logger.error(
                            f"cot_memref to a member `{member.name}` of the struct `{struct_tinfo.dstr()}`, is unknown"
                        )
                        return stmt_id
                    field_id = self.ctx.types_manager.types_trap[field_identifier]
                else:
                    self.logger.error(
                        f"cot_memref to a member `{member.name}` of not UDT `{struct_tinfo.dstr()}`, is unknown"
                    )
                    field_id = -1

                self.visitor.trap_generator.generate_var_acc(
                    self.ctx.curr_fn_name, stmt_id, field_id
                )

                break

        return stmt_id

    def cot_memptr(self, e: ida_hexrays.cexpr_t):
        """Struct/union member access via pointer (`x->m`); returns the node id."""
        loc_id = self.visitor.generate_location(self.visitor.binary_name, e)
        stmt_id = self.visitor.generate_node(loc_id, e, 60)
        self.visitor.generate_edge(e)

        # Get base type (strip pointer)
        base_tinfo = e.x.type
        if base_tinfo.is_ptr():
            base_tinfo = self.ctx.types_manager.strip_type(
                base_tinfo.get_pointed_object()
            )

        if str(base_tinfo) not in self.ctx.types_manager.types_trap:
            self.ctx.types_manager.write_type(base_tinfo)

        # Get UDT info
        udt_data = ida_typeinf.udt_type_data_t()
        if not base_tinfo.get_udt_details(udt_data):
            self.logger.error("cot_memptr: not a struct type")
            return stmt_id

        target_offset = e.m * 8

        for member in udt_data:
            if member.offset == target_offset:
                field_identifier = f"{base_tinfo!s}-{member.name}"

                if field_identifier not in self.ctx.types_manager.types_trap:
                    self.logger.error(f"Unknown field identifier {field_identifier}")
                    return stmt_id

                field_id = self.ctx.types_manager.types_trap[field_identifier]

                self.visitor.trap_generator.generate_var_acc(
                    self.ctx.curr_fn_name, stmt_id, field_id
                )

                break

        return stmt_id

    def cot_num(self, e: ida_hexrays.cexpr_t):
        """Integer constant, or enum member access(es) for an enum-formatted number."""

        def generate_num(stmt: int, value: int):
            # Decimal number string: exact, no int32/float ceiling. Matches upstream
            # CodeQL C++ (see https://github.com/github/codeql/issues/4691).
            trap = f'posintnumberliterals({stmt}, "{trap_escape(value)}")'
            trap_hex = f"posintnumberliterals({stmt}, {value} ({hex(value)}))"
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap_hex + "\n")

        def generate_neg_num(stmt: int, value: int):
            trap = f'negintnumberliterals({stmt}, "{trap_escape(value)}")'
            trap_hex = f"negintnumberliterals({stmt}, {value} ({hex(value)}))"
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap_hex + "\n")

        loc_id = self.visitor.generate_location(self.visitor.binary_name, e)

        if e.n.nf.is_enum():
            # Enum-formatted number: emit an access to the matching member(s).
            stmt_id = self.visitor.generate_node(loc_id, e, 105)  # plain_var_acc

            enum_name = e.n.nf.type_name
            value = ctypes.c_uint64(e.n._value).value

            enum_tif = ida_typeinf.tinfo_t()

            if not (enum_tif.get_named_type(None, enum_name) and enum_tif.is_enum()):
                return

            ei = ida_typeinf.enum_type_data_t()

            if not enum_tif.get_enum_details(ei):
                return

            enum_identifier = str(enum_tif)

            if enum_identifier not in self.ctx.types_manager.types_trap:
                self.ctx.types_manager.write_type(enum_tif)

            # 1. Exact member match
            idx = ei.find_member(value, 0)

            if idx >= 0:
                member = ei[idx]

                enum_member_identifier = f"{enum_tif}-{member.name}"

                if enum_member_identifier not in self.ctx.types_manager.types_trap:
                    self.ctx.types_manager.write_type(enum_tif)

                if enum_member_identifier not in self.ctx.types_manager.types_trap:
                    self.logger.error(
                        f"Unknown enum member identifier {enum_member_identifier}"
                    )
                    return

                enum_member_trap = self.ctx.types_manager.types_trap[
                    enum_member_identifier
                ]

                self.visitor.trap_generator.generate_var_acc(
                    self.ctx.curr_fn_name,
                    stmt_id,
                    enum_member_trap,
                )

                return

            # 2. Bitmask enum: one access per set single-bit flag
            if enum_tif.is_bitmask_enum():
                remaining = value

                for member in ei:
                    member_value = int(member.value)

                    # Skip 0 and multi-bit masks
                    if member_value == 0:
                        continue

                    if member_value & (member_value - 1):
                        continue

                    if remaining & member_value:
                        enum_member_identifier = f"{enum_tif}-{member.name}"

                        if (
                            enum_member_identifier
                            not in self.ctx.types_manager.types_trap
                        ):
                            self.ctx.types_manager.write_type(enum_tif)

                        if (
                            enum_member_identifier
                            not in self.ctx.types_manager.types_trap
                        ):
                            self.logger.error(
                                f"Unknown enum member identifier {enum_member_identifier}"
                            )
                            continue

                        enum_member_trap = self.ctx.types_manager.types_trap[
                            enum_member_identifier
                        ]

                        self.visitor.trap_generator.generate_var_acc(
                            self.ctx.curr_fn_name,
                            stmt_id,
                            enum_member_trap,
                        )

                        remaining &= ~member_value

                if remaining != 0:
                    self.logger.debug(
                        f"Unhandled bitmask bits {remaining:#x} in {enum_identifier}"
                    )

                return

            self.logger.debug(f"Unknown enum value {value} in {enum_identifier}")

            return

        else:
            # Plain literal. e.type has the real width/signedness (e.n doesn't),
            # so an unsigned 64-bit literal isn't sign-flipped to -1.
            svalue: int = reinterpret_raw_value(e.n._value, e.type)

            if svalue >= 0:
                stmt_id = self.visitor.generate_node(loc_id, e)
                self.visitor.generate_edge(e)
                generate_num(stmt_id, svalue)
            else:
                stmt_id = self.visitor.generate_node(
                    loc_id, e, 102
                )  # negintnumberliterals
                self.visitor.generate_edge(e)
                generate_neg_num(stmt_id, svalue)

    def cot_fnum(self, e: ida_hexrays.cexpr_t):
        """Floating-point constant."""

        def generate_fnum(stmt: int, value: float) -> None:
            # String column: exact decimal, or "NaN" / "Infinity" / "-Infinity"
            # -- the TRAP reader's float column has no token for -Infinity.
            if math.isnan(value):
                text = "NaN"
            elif math.isinf(value):
                text = "-Infinity" if value < 0 else "Infinity"
            else:
                text = format_trap_number(value)
            trap = f'floatnumberliterals({stmt}, "{trap_escape(text)}")'
            trap_hex = f"floatnumberliterals({stmt}, {value})"
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap_hex + "\n")

        loc_id = self.visitor.generate_location(self.visitor.binary_name, e)
        stmt_id = self.visitor.generate_node(loc_id, e)
        self.visitor.generate_edge(e)

        fnum = e.fpc.fnum
        try:
            value = fnum.float
        except SystemError:
            # SWIG's `.float` getter leaks a bare SystemError for some
            # extended-precision (80-bit x87) bit patterns. Fall back to kind.
            kind = fnum.get_kind()
            if kind == ida_ieee.FPV_PINF:
                value = float("inf")
            elif kind == ida_ieee.FPV_NINF:
                value = float("-inf")
            elif kind == ida_ieee.FPV_NAN:
                value = float("nan")
            else:
                self.logger.warning(
                    f"Could not convert fnum (kind={kind}) to float in "
                    f"{self.ctx.curr_fn_name}; emitting 0.0"
                )
                value = 0.0
        generate_fnum(stmt_id, value)

    def cot_str(self, e: ida_hexrays.cexpr_t):
        """String literal."""

        def generate_str(stmt: int, value: str) -> None:
            trap = f'stringliterals({stmt}, "{trap_escape(value)}")'
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap + "\n")

        loc_id = self.visitor.generate_location(self.visitor.binary_name, e)
        # stringliterals
        stmt_id = self.visitor.generate_node(loc_id, e, 63)
        self.visitor.generate_edge(e)
        generate_str(stmt_id, e.string)  # fmt: skip

    def cot_obj(self, e: ida_hexrays.cexpr_t):
        """Object reference: string literal or global variable access."""

        def generate_stringliteral(stmt: int, target: str):
            trap = f'stringliterals({stmt}, "{trap_escape(target)}")'
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap + "\n")

        def string_value() -> str:
            """Decoded strlit bytes at `obj_ea`, else the de-tagged display text.

            `e.print1()` is IDA's escaped display form (drops `\\n`, `"`->`'`).
            """
            ea = int(e.obj_ea)
            if ea not in (0, BADADDR_IDA):
                strtype = ida_nalt.get_str_type(ea)
                if strtype in (None, 0xFFFFFFFF):
                    strtype = ida_nalt.STRTYPE_C
                b = ida_bytes.get_strlit_contents(ea, -1, strtype)
                if b:
                    return b.decode("utf-8", "surrogateescape")
            return ida_pro.str2user(ida_lines.tag_remove(e.print1(None)))

        raw = ida_pro.str2user(ida_lines.tag_remove(e.print1(None)))
        name = raw.replace('\\"', "'").replace("\\\\n", "")

        match (e.refwidth, e.ea):
            case (-1, ea) if ea == BADADDR_IDA:
                # Already handled by its parent, a cot_call
                #              +--------+
                #          x   |asg     |   y
                #         +----|ea: 1234|----+
                #         |    +--------+    |
                #         |                  |
                #         |                  |
                # +-------v-------+  +-------v-------+
                # |any            |  |obj.-1 "String"|
                # |ea: unknown    |  |ea: BADADDR    |
                # +---------------+  +---------------+

                if cot_and_cit[self.visitor.get_parent(e).op] == "cot_call":
                    return
                loc_id = self.visitor.generate_location(self.visitor.binary_name, e)
                stmt_id = self.visitor.generate_node(loc_id, e, 63)  # cot_str
                self.visitor.generate_edge(e)
                generate_stringliteral(stmt_id, string_value())

            case (-1, _):
                # StringLiteral that is a call arg
                loc_id = self.visitor.generate_location(self.visitor.binary_name, e)
                # stringliterals
                stmt_id = self.visitor.generate_node(loc_id, e, 63)  # cot_str
                self.visitor.generate_edge(e)
                generate_stringliteral(stmt_id, string_value())

            case (w, _) if w > 0:
                # VarAccess on a global variable
                loc_id = self.visitor.generate_location(self.visitor.binary_name, e)
                stmt_id = self.visitor.generate_node(loc_id, e, 105)  # plain_var_acc

                is_local = name in self.ctx.lscopevars_trap
                self.logger.debug(f"Gvar candidate: name: {name}")
                self.logger.debug(f"Gvar candidate: is_local: {is_local}")

                if name not in self.ctx.gvars_trap:
                    var_trap_id = self.visitor.trap_generator.handler_gvar(
                        self.ctx.curr_fn_name, name, e.cexpr.type
                    )
                    self.ctx.gvars_trap[name] = var_trap_id

                self.visitor.trap_generator.generate_var_acc(
                    self.ctx.curr_fn_name, stmt_id, self.ctx.gvars_trap[name]
                )

                self.visitor.generate_edge(e)

            case _:
                self.logger.error("cot_obj type is unknown")
                self.logger.error(f"e.refwidth: {e.refwidth!s}")
                self.logger.error(f"e.ea: {hex(e.ea)!s}\n")

    def cot_var(self, e: ida_hexrays.cexpr_t):
        """Local variable access."""

        loc_id = self.visitor.generate_location(self.visitor.binary_name, e)
        stmt_id = self.visitor.generate_node(loc_id, e, 105)  # plain_var_acc
        self.visitor.generate_edge(e)

        if idaapi.IDA_SDK_VERSION < 930:
            var_name = e.v.getv().name
        else:
            lvar = self.ctx.cfunc.lvars[e.v.idx]
            var_name = lvar.name

        self.visitor.trap_generator.generate_var_acc(
            self.ctx.curr_fn_name, stmt_id, self.ctx.lscopevars_trap[var_name]
        )

    def cot_sizeof(self, e: ida_hexrays.cexpr_t):
        """`sizeof`, emitted as an intrinsic call to a synthetic `intrinsic_sizeof`."""
        loc_id = self.visitor.generate_location(self.visitor.binary_name, e)
        stmt_id = self.visitor.generate_node(loc_id, e)
        self.visitor.generate_edge(e)

        # Normally, helper functions are handled in cot_call before reaching this point.
        if "sizeof" not in self.ctx.synthetic_trap:
            self.logger.debug(f"Generating functions with {e.type}")

            decl = "__int64 intrinsic_sizeof();"

            tif = ida_typeinf.tinfo_t()
            _ = ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL)

            intrinsic_id = self.visitor.trap_generator.handler_function(
                "intrinsic_sizeof", decl, BADADDR_TRAP, BADADDR_TRAP, func_tinfo=tif
            )
            self.logger.debug(f"Functions to {intrinsic_id}")
            self.ctx.synthetic_trap["sizeof"] = intrinsic_id

        self.logger.debug(
            f"Generating intrinsics with {self.ctx.synthetic_trap['sizeof']}"
        )
        self._generate_helper(stmt_id, self.ctx.synthetic_trap["sizeof"])

    def _generate_helper(self, stmt: int, target: int):
        trap = f"intrinsics({stmt}, {target})"
        self.visitor.write_trap(self.ctx.curr_fn_name, trap)
        self.logger.trap(trap + "\n")

    def cot_helper(self, e: ida_hexrays.cexpr_t):
        """Compiler helper/intrinsic reference, emitted as an intrinsic call."""

        loc_id = self.visitor.generate_location(self.visitor.binary_name, e)
        stmt_id = self.visitor.generate_node(loc_id, e)
        self.visitor.generate_edge(e)

        # Normally, helper functions are handled in cot_call before reaching this point.
        self._generate_helper(stmt_id, self._ensure_synthetic(e.helper, e.type))

    def cot_label(self, e: ida_hexrays.cexpr_t) -> None:
        """Emit a `labels` row when the expression carries a label."""

        def generate_label(label_idx: int, node: int) -> None:
            trap = f"labels({label_idx}, {node})"
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap + "\n")

        l_num = e.label_num

        # There is a label associated with this cot_*
        if l_num != -1:
            l_num_trap = self.ctx.label_trap.setdefault(
                l_num, self.ctx.increment_global_id()
            )
            stmt_id = self.visitor.get_trap_id_by_citem(e)
            generate_label(l_num_trap, stmt_id)

    def cot_type(self, e: ida_hexrays.cexpr_t) -> None:
        # cot_type carries a type annotation in the AST but is not a runtime value;
        # no trap is emitted, so it falls through to the generic missing handler.
        self.missing(e)

    # cit_

    def cit_block(self, i: ida_hexrays.cinsn_t) -> None:
        """Block statement; the edge is skipped for the root block (no parent)."""

        def generate_block(self, stmt: int) -> None:
            trap = f"cit_blocks({stmt})"
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap + "\n")

        loc_id = self.visitor.generate_location(self.visitor.binary_name, i)
        self.visitor.generate_node(loc_id, i)
        if self.visitor.get_parent(i) is not None:
            self.visitor.generate_edge(i)

    def cit_expr(self, i: ida_hexrays.cinsn_t) -> None:
        """Expression statement."""

        _ = self.generic(i)

        return

    def cit_try(self, i: ida_hexrays.cinsn_t) -> None:
        """C++ try statement.

        Hex-Rays flattens tried stmts, catch bodies and caught-object exprs into one
        child list with no boundaries. `i.ctry`/`ctry.catchs` are only reachable here
        (no `cit_catch` opcode), so the boundaries must be recorded now.
        """

        stmt_id = self.generic(i)

        ctry = i.ctry

        try_body_len = len(list(ctry))

        trap = f"trystmts({stmt_id}, {try_body_len})"
        self.visitor.write_trap(self.ctx.curr_fn_name, trap)
        self.logger.trap(trap + "\n")

        # Children: [tried stmts][h0 body][h0 param][h1 body][h1 param]...
        # A caught-object expr follows its own handler body, not the end of the list.
        child_cursor = try_body_len
        for index, handler in enumerate(ctry.catchs):
            body_len = len(list(handler))
            handler_id = self.ctx.increment_global_id()

            trap = (
                f"catch_handlers({handler_id}, {stmt_id}, {index}, "
                f"{child_cursor}, {body_len})"
            )
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap + "\n")

            child_cursor += body_len

            for catch_expr in handler.exprs:
                if catch_expr.obj.op != ida_hexrays.cot_empty:
                    caught_type_id = self.ctx.types_manager.write_type(
                        catch_expr.obj.type
                    )
                    param_trap = (
                        f"catch_handler_params({handler_id}, "
                        f"{child_cursor}, {caught_type_id})"
                    )
                    self.visitor.write_trap(self.ctx.curr_fn_name, param_trap)
                    self.logger.trap(param_trap + "\n")
                    child_cursor += 1

        return

    def cit_switch(self, i: ida_hexrays.cinsn_t) -> None:
        """Switch statement.

        Each `ccase_t` body is visited as a plain child, so its `values` (empty for
        `default`) are only reachable here and must be recorded now.
        """

        stmt_id = self.generic(i)

        cswitch = i.cswitch

        # The visitor walks the case bodies before `cswitch.expr`
        # so case `index` is child `index` of the switch node.
        for index, case in enumerate(cswitch.cases):
            case_id = self.ctx.increment_global_id()

            trap = f"switch_cases({case_id}, {stmt_id}, {index}, {index})"
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap + "\n")

            # Raw uint64: sign it per the controlling expr's type (negative cases).
            for raw in case.values:
                value = reinterpret_raw_value(raw, cswitch.expr.type)
                trap = f'switch_case_values({case_id}, "{trap_escape(value)}")'
                self.visitor.write_trap(self.ctx.curr_fn_name, trap)
                self.logger.trap(trap + "\n")

        return

    def cit_throw(self, i: ida_hexrays.cinsn_t) -> None:
        """C++ throw statement."""

        _ = self.generic(i)

        return

    def cit_asm(self, i: ida_hexrays.cinsn_t) -> None:
        """Inline asm statement.

        `i.casm` only holds the instruction EAs (reachable only here); their text is
        not in the ctree, so it is rebuilt from the database.
        """

        stmt_id = self.generic(i)

        for index, ea in enumerate(i.casm):
            insn_id = self.ctx.increment_global_id()
            mnemonic = ida_ua.print_insn_mnem(ea)
            text = ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0))

            trap = (
                f"asm_stmt_insns({insn_id}, {stmt_id}, {index}, {float(ea)}, "
                f'"{trap_escape(mnemonic)}", "{trap_escape(text)}")'
            )
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap + "\n")

        return

    def cit_goto(self, i: ida_hexrays.cinsn_t):
        """Goto statement."""

        def generate_goto(goto: int, label_idx: int, label_name: str) -> None:
            trap = f'gotostmts({goto}, {label_idx}, "{trap_escape(label_name)}")'
            self.visitor.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap + "\n")

        l_num = i.cgoto.label_num

        l_num_trap = self.ctx.label_trap.setdefault(
            l_num, self.ctx.increment_global_id()
        )
        l_name = self._goto_label_name(i, l_num)

        loc_id = self.visitor.generate_location(self.visitor.binary_name, i)
        stmt_id = self.visitor.generate_node(loc_id, i)
        self.visitor.generate_edge(i)

        generate_goto(stmt_id, l_num_trap, l_name)

    def _goto_label_name(self, i: ida_hexrays.cinsn_t, l_num: int) -> str:
        """Resolve a goto's target label name.

        IDA 9.4's `dstr()` always renders synthetic `LABEL_<n>`, so read the
        function-local (`GN_LOCAL`) name at the label EA; fall back to `dstr()`.
        """
        target = self.ctx.cfunc.find_label(l_num)
        if target is not None and target.ea != BADADDR_IDA:
            name = ida_name.get_ea_name(target.ea, ida_name.GN_LOCAL)
            if name:
                return name
        return i.dstr().removeprefix("goto ").removesuffix(";")

    # utils

    def generic(self, citem: ida_hexrays.citem_t) -> int:
        """Emit location, node and edge for a ctree item; returns the node id."""

        loc_id = self.visitor.generate_location(self.visitor.binary_name, citem)
        stmt_id = self.visitor.generate_node(loc_id, citem)
        self.visitor.generate_edge(citem)

        return stmt_id

    def missing(self, citem: ida_hexrays.citem_t) -> None:
        """Fallback for items with no dedicated handler: log, emit a generic node."""

        if citem.is_expr():
            self.logger.debug(
                f"expr: handler missing {cot_and_cit[citem.op]} @{hex(int(citem.ea))} \n"
            )
        else:
            self.logger.debug(
                f"insn: handler missing {cot_and_cit[citem.op]} @{hex(int(citem.ea))} \n"
            )

        self.generic(citem)
