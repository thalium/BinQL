import json
import os
import sys
from typing import TYPE_CHECKING, cast

import ida_ida
import ida_typeinf
import idaapi

if TYPE_CHECKING:
    from decompiler.ida.types import Context

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

from decompiler.ida.utils import reinterpret_raw_value, trap_escape
from utils.logger import TrapLogger
from utils.trap import trap_generator_t

cc_map = {
    ida_typeinf.CM_CC_FASTCALL: "__fastcall",
    ida_typeinf.CM_CC_CDECL: "__cdecl",
    ida_typeinf.CM_CC_STDCALL: "__stdcall",
    ida_typeinf.CM_CC_THISCALL: "__thiscall",
    ida_typeinf.CM_CC_UNKNOWN: "unknown",
    ida_typeinf.CM_CC_ELLIPSIS: "__cdecl(...)",
    ida_typeinf.CM_CC_PASCAL: "__pascal",
    ida_typeinf.CM_CC_SPOILED: "spoiled",
    ida_typeinf.CM_CC_GOLANG: "go",
    ida_typeinf.CM_CC_SPECIALE: "special(...)",
    ida_typeinf.CM_CC_SPECIALP: "special purged",
}

# Source: https://gist.github.com/michal-kapala/e27386392cfd54fa2506a814dc5a3e5d
function_call_convention_map = {
    ida_typeinf.CM_CC_INVALID: (0, "invalid"),
    ida_typeinf.CM_CC_UNKNOWN: (1, "unknown"),
    ida_typeinf.CM_CC_VOIDARG: (2, "void"),
    ida_typeinf.CM_CC_CDECL: (3, "__cdecl"),
    ida_typeinf.CM_CC_ELLIPSIS: (4, "__cdecl(...)"),
    ida_typeinf.CM_CC_STDCALL: (5, "__stdcall"),
    ida_typeinf.CM_CC_PASCAL: (6, "__pascal"),
    ida_typeinf.CM_CC_FASTCALL: (7, "__fastcall"),
    ida_typeinf.CM_CC_THISCALL: (8, "__thiscall"),
    ida_typeinf.CM_CC_SWIFT: (9, "swift"),
    ida_typeinf.CM_CC_SPOILED: (10, "spoiled"),
    ida_typeinf.CM_CC_GOLANG: (11, "golang"),
    ida_typeinf.CM_CC_SPECIALE: (12, "special(...)"),
    ida_typeinf.CM_CC_SPECIALP: (13, "special purged"),
    ida_typeinf.CM_CC_SPECIAL: (14, "__usercall"),
}

# source: `tf_shortcuts` in typeinf.hpp
types_map = {
    # byte, `BYTE`
    ida_typeinf.BTF_BYTE: 0,
    # unknown, `unknown`
    ida_typeinf.BTF_UNK: 1,
    # void, `void`
    ida_typeinf.BTF_VOID: 2,
    # signed char, `char`
    ida_typeinf.BTF_CHAR: 4,
    # unsigned char, `unsigned char`
    ida_typeinf.BTF_UCHAR: 5,
    # byte, `__int8`
    ida_typeinf.BT_INT8: 3,
    # signed byte, `__int8`
    ida_typeinf.BTF_INT8: 3,
    # unsigned byte, `unsigned __int8`
    ida_typeinf.BTF_UINT8: 6,
    # short, `__int16`
    ida_typeinf.BT_INT16: 7,
    # signed short, `__int16`
    ida_typeinf.BTF_INT16: 8,
    # unsigned short, `unsigned __int16`
    ida_typeinf.BTF_UINT16: 9,
    # int, `__int32`
    ida_typeinf.BT_INT32: 10,
    # signed int, `__int32`
    ida_typeinf.BTF_INT32: 11,
    # unsigned int, `unsigned __int32`
    ida_typeinf.BTF_UINT32: 12,
    # long, `__int64`
    ida_typeinf.BT_INT64: 13,
    # signed long, `signed __int64`
    ida_typeinf.BTF_INT64: 14,
    # unsigned long, `unsigned __int64`
    ida_typeinf.BTF_UINT64: 15,
    ida_typeinf.BT_INT128: 16,
    # signed 128-bit value, `__int128`
    ida_typeinf.BTF_INT128: 17,
    # unsigned 128-bit value, `unsigned __int128`
    ida_typeinf.BTF_UINT128: 18,
    # int, `int`
    ida_typeinf.BTF_INT: 19,
    ida_typeinf.BT_UNK_WORD: 20,
    # unsigned int, `unsigned int`
    ida_typeinf.BTF_UINT: 21,
    # signed int, `signed int`
    ida_typeinf.BTF_SINT: 22,
    # boolean, `bool`
    ida_typeinf.BTF_BOOL: 23,
    # float, `float`
    ida_typeinf.BTF_FLOAT: 24,
    # double, `double`
    ida_typeinf.BTF_DOUBLE: 25,
    # long double, `long double`
    ida_typeinf.BTF_LDOUBLE: 26,
    # float (variable size), `variable size float`
    ida_typeinf.BTF_TBYTE: 27,
    # UNKNOWN
    ida_typeinf.BT_UNKNOWN: 28,
    # _WORD (16)
    ida_typeinf.BT_UNK_WORD: 29,
    # _BYTE (17)
    ida_typeinf.BTF_BYTE: 30,
    # _BYTE (17)
    ida_typeinf.BT_UNK_BYTE: 31,
    # _DWORD (32)
    ida_typeinf.BT_UNK_QWORD: 32,
    # _DWORD (33)
    ida_typeinf.BT_UNK_DWORD: 33,
    # _OWORD (49)
    ida_typeinf.BT_UNK_OWORD: 34,
    # Typedef
    ida_typeinf.BTF_TYPEDEF: 35,
}


def _safe_get_type_name(tinfo: ida_typeinf.tinfo_t) -> str | None:
    """Type name, ``""`` if unnamed, or None if the name isn't valid UTF-8.

    The SWIG binding raises ``UnicodeDecodeError`` on non-UTF-8 names (DWARF
    anon types in Android GKI ``vmlinux``); callers treat None as "named but
    opaque" and use a synthetic name rather than abort the run.
    """
    try:
        return tinfo.get_type_name()
    except UnicodeDecodeError:
        return None


# C11 <stdatomic.h> typedefs IDA carries as a bare name (BT_UNK). The dbscheme
# has no atomic qualifier, so resolve them to the plain underlying type.
_STDATOMIC_UNDERLYING = {
    "atomic_bool": "bool",
    "atomic_char": "char",
    "atomic_schar": "signed char",
    "atomic_uchar": "unsigned char",
    "atomic_short": "short",
    "atomic_ushort": "unsigned short",
    "atomic_int": "int",
    "atomic_uint": "unsigned int",
    "atomic_long": "long",
    "atomic_ulong": "unsigned long",
    "atomic_llong": "long long",
    "atomic_ullong": "unsigned long long",
    "atomic_char16_t": "unsigned __int16",
    "atomic_char32_t": "unsigned __int32",
    "atomic_wchar_t": "wchar_t",
    "atomic_intptr_t": "long",
    "atomic_uintptr_t": "unsigned long",
    "atomic_size_t": "unsigned long",
    "atomic_ptrdiff_t": "long",
    "atomic_intmax_t": "long long",
    "atomic_uintmax_t": "unsigned long long",
}
for _w in (8, 16, 32, 64):
    for _sign, _prefix in (("int", "__int"), ("uint", "unsigned __int")):
        for _fam in ("least", "fast"):
            _STDATOMIC_UNDERLYING[f"atomic_{_sign}_{_fam}{_w}_t"] = f"{_prefix}{_w}"
del _w, _sign, _prefix, _fam


def _parse_c_type(decl: str) -> ida_typeinf.tinfo_t | None:
    """Resolve a C type expression against the target's type library, or None."""
    out = ida_typeinf.tinfo_t()
    name = ida_typeinf.parse_decl(out, None, f"{decl} __t;", ida_typeinf.PT_SIL)
    if name is None or out.empty():
        return None
    return out


class TypesManager:
    def __init__(self, ctx: "Context") -> None:
        """Per-run type manager; `types_trap` dedups emissions by `str(tinfo)`.

        `unionfield_idx` hands out sequential field indices per union (fields all
        sit at offset 0), keyed by trap id since anonymous unions share "<anon>".
        """
        self.logger: TrapLogger = TrapLogger.from_env()
        self.ctx = ctx
        self.trap_generator = trap_generator_t(ctx)
        self.types_trap: dict[str, int] = {}
        self.unionfield_idx: dict[int, int] = {}

    def flush(self) -> None:
        self.trap_generator.flush()

    @staticmethod
    def strip_type(tinfo: ida_typeinf.tinfo_t) -> ida_typeinf.tinfo_t:
        stripped_tinfo_t = ida_typeinf.tinfo_t(tinfo)
        stripped_tinfo_t.set_modifiers(0)
        return stripped_tinfo_t

    @staticmethod
    def _is_basic_type(tinfo: ida_typeinf.tinfo_t) -> bool:
        t = ida_typeinf.tinfo_t(tinfo)

        return (
            t.is_void()
            or t.is_bool()
            or t.is_integral()
            or t.is_floating()
            or t.is_bitfield()
        )

    @staticmethod
    def effective_cc(funcdata: ida_typeinf.func_type_data_t) -> int:
        """Function cc, or the database default when unset (IDA's `get_effective_cc`)."""
        if idaapi.IDA_SDK_VERSION >= 920:
            cc = funcdata.get_explicit_cc()
            return ida_ida.inf_get_callcnv() if cc <= ida_typeinf.CM_CC_UNKNOWN else cc
        # Legacy cm_t also carries memory-model bits
        cc = funcdata.cc & ida_typeinf.CM_CC_MASK
        if cc <= ida_typeinf.CM_CC_UNKNOWN:
            cc = ida_ida.inf_get_cc_cm() & ida_typeinf.CM_CC_MASK
        return cc

    def write_type(self, tinfo: ida_typeinf.tinfo_t) -> int:
        tinfo_name = str(tinfo)

        if tinfo_name in self.types_trap:
            return self.types_trap[tinfo_name]

        if self._is_basic_type(tinfo):
            return self._write_basic_type(tinfo)
        else:
            return self._write_complex_type(tinfo)

    def _write_basic_type(self, tinfo: ida_typeinf.tinfo_t) -> int:
        tinfo_name = str(tinfo)

        type_id = self.ctx.increment_global_id()
        size = tinfo.get_size(p_effalign=None, gts_code=0)
        trap = f"basic_types({type_id}, {json.dumps(tinfo_name)}, {self.as_codeql_type(tinfo)}, {float(size)})"
        self.trap_generator.write_trap("types", trap)
        self.types_trap[tinfo_name] = type_id

        return self.types_trap[tinfo_name]

    def _write_complex_type(self, tinfo: ida_typeinf.tinfo_t) -> int:

        if tinfo.is_ptr():
            return self._write_pointer_type(tinfo)
        if tinfo.is_const():
            return self._write_const_type(tinfo)
        if tinfo.is_struct():
            return self._write_struct_type(tinfo)
        if tinfo.is_union():
            return self._write_union_type(tinfo)
        if tinfo.is_enum():
            return self._write_enum_type(tinfo)
        if tinfo.is_array():
            return self._write_array_type(tinfo)
        if tinfo.is_func():
            return self._write_func_type(tinfo)
        if tinfo.is_volatile():
            return self._write_volatile_type(tinfo)
        if tinfo.is_forward_decl():
            return self._write_forward_decl_type(tinfo)
        # Typedefs are resolved to their underlying type rather than emitted as a
        # distinct trap row. A dedicated typedef trap kind would be cleaner but is
        # not yet implemented in the dbscheme.
        if tinfo.is_typedef():
            return self.write_type(TypesManager.resolve_typedef_once(tinfo))

        # Named type with no local definition (e.g. PDB/SxS-only struct):
        # BT_UNK, so no is_*() above matched. Emit as opaque forward decl.
        type_name = _safe_get_type_name(tinfo)
        if type_name is None:
            self.logger.warning(
                f"Named type with non-UTF-8 name (realtype={hex(tinfo.get_realtype())}); "
                "emitting as opaque/forward type queriable in CodeQL"
            )
            return self._write_forward_decl_type(tinfo)
        if type_name:
            atomic_base = _STDATOMIC_UNDERLYING.get(type_name)
            if atomic_base is not None:
                base_tinfo = _parse_c_type(atomic_base)
                if base_tinfo is not None:
                    resolved = self.write_type(base_tinfo)
                    self.types_trap[str(tinfo)] = resolved
                    return resolved
            self.logger.warning(
                f"Unresolvable named type '{type_name}' (realtype={hex(tinfo.get_realtype())}); emitting as opaque/forward type queriable in CodeQL"
            )
            return self._write_forward_decl_type(tinfo)

        raise NotImplementedError(
            f"Unsupported tinfo: {tinfo}, {tinfo.get_realtype()} ({hex(tinfo.get_realtype())})\n - is_struct: {tinfo.is_struct()}\n - is_forward_decl: {tinfo.is_forward_decl()}\n - is_typedef: {tinfo.is_typedef()}\n - is_ptr: {tinfo.is_ptr()}"
        )

    @staticmethod
    def resolve_typedef_once(tinfo: ida_typeinf.tinfo_t) -> ida_typeinf.tinfo_t:
        t = ida_typeinf.tinfo_t(tinfo)

        # Only unwrap if it's a typedef
        if t.is_typedef():
            try:
                next_name = t.get_next_type_name()
            except UnicodeDecodeError:
                next_name = None
            if next_name:
                out = ida_typeinf.tinfo_t()
                if out.get_named_type(next_name):
                    return out

        return t

    def _write_forward_decl_type(self, tinfo: ida_typeinf.tinfo_t) -> int:
        tinfo_name = str(tinfo)
        type_id = self.ctx.increment_global_id()

        name = _safe_get_type_name(tinfo) or tinfo_name

        trap = f'forward_types({type_id}, "{trap_escape(name)}")'
        self.trap_generator.write_trap("types", trap)

        self.types_trap[tinfo_name] = type_id
        return type_id

    @staticmethod
    def _strip_cv_qualifiers(tinfo: ida_typeinf.tinfo_t) -> ida_typeinf.tinfo_t:
        # For arrays, const/volatile qualifiers live on the element type, not
        # on the array's own modifier byte, so `set_modifiers(0)` on a plain
        # copy of the array tinfo has no effect on is_const()/is_volatile()
        # and previously caused infinite recursion (e.g. "const wchar_t[]").
        if tinfo.is_array():
            array_data = ida_typeinf.array_type_data_t()
            if not tinfo.get_array_details(array_data):
                raise ValueError(f"Failed to get array details for {tinfo}")
            array_data.elem_type.set_modifiers(0)
            stripped = ida_typeinf.tinfo_t()
            stripped.create_array(array_data)
            return stripped

        stripped = ida_typeinf.tinfo_t(tinfo)
        stripped.set_modifiers(0)
        return stripped

    @staticmethod
    def _strip_cv_via_serialize(
        tinfo: ida_typeinf.tinfo_t,
    ) -> ida_typeinf.tinfo_t | None:
        """Clear a const/volatile bit `set_modifiers(0)` can't, or None.

        Three attempts: re-resolve by name; strip the modifier bits from the
        serialized leading byte; rebuild a struct/union from its members.
        Enums are left alone -- rebuilding one re-keys its constants and breaks
        the cot_num lookup.
        """
        idati = ida_typeinf.get_idati()

        name = _safe_get_type_name(tinfo)
        if name:
            byname = ida_typeinf.tinfo_t()
            if byname.get_named_type(idati, name) and not (
                byname.is_const() or byname.is_volatile()
            ):
                return byname

        # BTM_CONST 0x40 / BTM_VOLATILE 0x80 live in the leading type byte.
        out = None
        try:
            serialized = tinfo.serialize()
        except Exception:
            serialized = None
        if serialized and serialized[0] and serialized[0][0] & 0xC0:
            patched = bytes([serialized[0][0] & ~0xC0]) + serialized[0][1:]
            cand = ida_typeinf.tinfo_t()
            if cand.deserialize(idati, patched, *serialized[1:]):
                out = cand

        src = out if out is not None else ida_typeinf.tinfo_t(tinfo)
        if (src.is_const() or src.is_volatile()) and src.is_udt():
            udt = ida_typeinf.udt_type_data_t()
            if src.get_udt_details(udt):
                rebuilt = ida_typeinf.tinfo_t()
                bt = ida_typeinf.BTF_UNION if udt.is_union else ida_typeinf.BTF_STRUCT
                if rebuilt.create_udt(udt, bt) and not (
                    rebuilt.is_const() or rebuilt.is_volatile()
                ):
                    out = rebuilt

        return out

    def _write_type_ignoring_cv(self, tinfo: ida_typeinf.tinfo_t) -> int:
        """Last-resort writer for a cv bit `set_modifiers(0)` can't clear (some
        PDB-derived structs); bypasses write_type(), which would recurse forever."""
        tinfo_name = str(tinfo)
        if tinfo_name in self.types_trap:
            return self.types_trap[tinfo_name]
        if tinfo.is_ptr():
            return self._write_pointer_type(tinfo)
        if tinfo.is_struct():
            return self._write_struct_type(tinfo)
        if tinfo.is_union():
            return self._write_union_type(tinfo)
        if tinfo.is_enum():
            return self._write_enum_type(tinfo)
        if tinfo.is_array():
            return self._write_array_type(tinfo)
        if tinfo.is_func():
            return self._write_func_type(tinfo)
        if self._is_basic_type(tinfo):
            return self._write_basic_type(tinfo)
        return self._write_forward_decl_type(tinfo)

    def _write_volatile_type(self, tinfo: ida_typeinf.tinfo_t) -> int:
        tinfo_name = str(tinfo)

        stripped = TypesManager._strip_cv_qualifiers(tinfo)
        if stripped.is_volatile():
            forced = TypesManager._strip_cv_via_serialize(stripped)
            if forced is not None and not forced.is_volatile():
                base = self.write_type(forced)
            else:
                self.logger.warning(
                    f"Could not strip volatile qualifier from tinfo {tinfo!r} "
                    f"(stripped={stripped!r} still reports is_volatile()); "
                    "writing base type directly, ignoring the stuck bit"
                )
                base = self._write_type_ignoring_cv(stripped)
            type_id = self.ctx.increment_global_id()
            trap = f"volatile_types({type_id}, {base})"
            self.trap_generator.write_trap("types", trap)
            self.types_trap[tinfo_name] = type_id
            return type_id

        base = self.write_type(stripped)
        type_id = self.ctx.increment_global_id()

        trap = f"volatile_types({type_id}, {base})"
        self.trap_generator.write_trap("types", trap)
        self.types_trap[tinfo_name] = type_id

        return type_id

    def _write_pointer_type(self, tinfo: ida_typeinf.tinfo_t) -> int:
        tinfo_name = str(tinfo)

        levels = 0
        current = ida_typeinf.tinfo_t(tinfo)

        while current.is_ptr():
            pointed = current.get_pointed_object()
            if not pointed:
                break
            current = pointed
            levels += 1

        underlying_type = self.write_type(current)
        type_id = self.ctx.increment_global_id()

        trap = f"pointer_types({type_id}, {underlying_type}, {levels})"
        self.trap_generator.write_trap("types", trap)
        self.types_trap[tinfo_name] = type_id

        return type_id

    def _write_const_type(self, tinfo: ida_typeinf.tinfo_t) -> int:
        tinfo_name = str(tinfo)

        stripped = TypesManager._strip_cv_qualifiers(tinfo)
        if stripped.is_const():
            forced = TypesManager._strip_cv_via_serialize(stripped)
            if forced is not None and not forced.is_const():
                base = self.write_type(forced)
            else:
                self.logger.warning(
                    f"Could not strip const qualifier from tinfo {tinfo!r} "
                    f"(stripped={stripped!r} still reports is_const()); "
                    "writing base type directly, ignoring the stuck bit"
                )
                base = self._write_type_ignoring_cv(stripped)
            type_id = self.ctx.increment_global_id()
            trap = f"const_types({type_id}, {base})"
            self.trap_generator.write_trap("types", trap)
            self.types_trap[tinfo_name] = type_id
            return type_id

        base = self.write_type(stripped)
        type_id = self.ctx.increment_global_id()

        trap = f"const_types({type_id}, {base})"
        self.trap_generator.write_trap("types", trap)
        self.types_trap[tinfo_name] = type_id

        return type_id

    def _write_struct_type(self, tinfo: ida_typeinf.tinfo_t) -> int:
        tinfo_name = str(tinfo)
        struct_name = _safe_get_type_name(tinfo) or "<anonymous>"
        struct_size = tinfo.get_size()

        struct_id = self.ctx.increment_global_id()
        trap = f'struct_types({struct_id}, "{trap_escape(struct_name)}", {float(struct_size)})'
        self.trap_generator.write_trap("types", trap)
        self.types_trap[tinfo_name] = struct_id

        udt_data = ida_typeinf.udt_type_data_t()
        if tinfo.get_udt_details(udt_data):
            for m in udt_data:
                field_id = self._write_udt_field(owner_id=struct_id, udt=tinfo, field=m)
                self.logger.debug(f"struct_fields {tinfo_name}-{m.name} -> {field_id}")
                field_identifier = f"{tinfo_name}-{m.name}"
                self.types_trap[field_identifier] = field_id

        return struct_id

    def _write_union_type(self, tinfo: ida_typeinf.tinfo_t) -> int:
        tinfo_name = str(tinfo)
        union_name: str = str(_safe_get_type_name(tinfo) or "<anon>")

        union_id = self.ctx.increment_global_id()
        self.unionfield_idx[union_id] = 0
        trap = f'union_types({union_id}, "{trap_escape(union_name)}")'
        self.trap_generator.write_trap("types", trap)
        self.types_trap[tinfo_name] = union_id

        udt_data = ida_typeinf.udt_type_data_t()
        if tinfo.get_udt_details(udt_data):
            for m in udt_data:
                field_id = self._write_udt_field(owner_id=union_id, udt=tinfo, field=m)
                self.logger.debug(f"union_fields {tinfo_name}-{m.name} -> {field_id}")
                field_identifier = f"{tinfo_name}-{m.name}"
                self.types_trap[field_identifier] = field_id

        return union_id

    def _write_udt_field(
        self, owner_id: int, udt: ida_typeinf.tinfo_t, field: ida_typeinf.udm_t
    ) -> int:
        if str(field.type) not in self.types_trap:
            self.write_type(field.type)

        field_name = field.name or "<anon>"
        field_type = self.types_trap[str(field.type)]

        # An udt is union OR struct, mutual exclusivity
        field_offset = field.offset // 8
        # For union members
        # Sequential index because all union fields share the same offset to null value
        if udt.is_union():
            field_offset = self.unionfield_idx[owner_id]
            self.unionfield_idx[owner_id] += 1

        field_id = self.ctx.increment_global_id()
        trap = f'fields({field_id}, "{trap_escape(field_name)}", {field_type}, {field_offset}, {owner_id})'
        self.trap_generator.write_trap("types", trap)

        return field_id

    def _write_enum_type(self, tinfo: ida_typeinf.tinfo_t) -> int:
        ei = ida_typeinf.enum_type_data_t()
        enum_id = self.ctx.increment_global_id()
        if tinfo.get_enum_details(ei):
            enum_identifier = str(tinfo)

            trap = f'enum_types({enum_id}, "{trap_escape(enum_identifier)}", {tinfo.get_size()})'
            self.trap_generator.write_trap("types", trap)
            self.types_trap[enum_identifier] = enum_id

            for member in ei:
                _ = self._write_enum_constant(enum_id, enum_identifier, member, tinfo)

        return enum_id

    def _write_enum_constant(
        self,
        enum_id: int,
        enum_name: str,
        member: ida_typeinf.enum_member_t,
        enum_tinfo: ida_typeinf.tinfo_t,
    ) -> int:
        const_name = member.name
        # Exact value, true width/sign -- decimal number string, no int32 ceiling.
        const_value = reinterpret_raw_value(member.value, enum_tinfo)

        const_id = self.ctx.increment_global_id()

        trap = (
            f'enum_constants({const_id}, "{trap_escape(const_name)}", '
            f'"{trap_escape(const_value)}", {enum_id})'
        )
        self.trap_generator.write_trap("types", trap)

        enum_constant_identifier = f"{enum_name}-{const_name}"

        self.types_trap[enum_constant_identifier] = const_id

        return const_id

    def _write_array_type(self, tinfo: ida_typeinf.tinfo_t) -> int:
        tinfo_name = str(tinfo)
        type_id = self.ctx.increment_global_id()

        array_data = ida_typeinf.array_type_data_t()
        if not tinfo.get_array_details(array_data):
            raise ValueError(f"Failed to get array details for {tinfo}")

        if str(array_data.elem_type) not in self.types_trap:
            self.write_type(array_data.elem_type)

        array_count = array_data.nelems
        array_size = array_count * array_data.elem_type.get_size()
        target = self.types_trap[str(array_data.elem_type)]

        trap = f"array_types({type_id}, {target}, {array_count}, {float(array_size)})"
        self.trap_generator.write_trap("types", trap)
        self.types_trap[tinfo_name] = type_id

        return type_id

    def _write_unknown_type(self) -> int:
        """Opaque placeholder type row for a tinfo IDA won't let us decompose
        (e.g. a partial `__high`/`__low` prototype). Deduped."""
        name = "<unknown>"
        if name in self.types_trap:
            return self.types_trap[name]
        type_id = self.ctx.increment_global_id()
        self.trap_generator.write_trap(
            "types", f'forward_types({type_id}, "{trap_escape(name)}")'
        )
        self.types_trap[name] = type_id
        return type_id

    @staticmethod
    def _recover_partial_func(
        tinfo: ida_typeinf.tinfo_t,
    ) -> ida_typeinf.func_type_data_t | None:
        """Re-parse a partial func tinfo's printed prototype into a full one, or
        None. A declarator name is injected before the parameter list."""
        proto = str(tinfo)
        depth = 0
        split = -1
        for i, ch in enumerate(proto):
            if ch == "(":
                if depth == 0:
                    split = i
                    break
                depth += 1
            elif ch == ")":
                depth -= 1
        if split <= 0:
            return None
        ret, params = proto[:split].rstrip(), proto[split:]
        # get_idati(): the params reference IDB-local named types.
        idati = ida_typeinf.get_idati()
        for decl in (f"{ret} __f{params};", f"{ret} (*__f){params};"):
            parsed = ida_typeinf.tinfo_t()
            if ida_typeinf.parse_decl(parsed, idati, decl, ida_typeinf.PT_SIL) is None:
                continue
            if parsed.is_funcptr():
                pointed = parsed.get_pointed_object()
                if pointed is None:
                    continue
                parsed = pointed
            funcdata = ida_typeinf.func_type_data_t()
            if parsed.is_func() and parsed.get_func_details(funcdata):
                return funcdata
        return None

    def _write_func_type(self, tinfo: ida_typeinf.tinfo_t) -> int:
        tinfo_name = str(tinfo)
        funcdata = ida_typeinf.func_type_data_t()

        # A partial prototype (e.g. `_QWORD __high(CFX_ByteString)`) is_func()
        # but has no decomposable details -- usually the argloc solver failing,
        # not the signature. Retry without arglocs (we never emit them), then
        # re-parse the printed prototype; only then fall back to a degenerate
        # row, so the function itself still gets registered rather than raising
        # (seen on foxit librdk.so: raising dropped ~11-14 functions + callers).
        gtd_no_arglocs = getattr(ida_typeinf, "GTD_NO_ARGLOCS", 1)
        if not tinfo.get_func_details(funcdata):
            recovered = None
            if tinfo.get_func_details(funcdata, gtd_no_arglocs):
                recovered = funcdata
            if recovered is None:
                recovered = TypesManager._recover_partial_func(tinfo)
            if recovered is not None:
                funcdata = recovered
            else:
                self.logger.warning(
                    f'Partial func tinfo "{tinfo}" has no func_type_data; '
                    "emitting degenerate func_type"
                )
                type_id = self.ctx.increment_global_id()
                ret_type = self._write_unknown_type()
                self.trap_generator.write_trap(
                    "types", f'func_types({type_id}, {ret_type}, "unknown")'
                )
                self.types_trap[tinfo_name] = type_id
                return type_id

        ret_type = self.write_type(funcdata.rettype)
        type_id = self.ctx.increment_global_id()

        func_cc = TypesManager.effective_cc(funcdata)
        _, cc_name = function_call_convention_map.get(func_cc, str(func_cc))
        trap = f'func_types({type_id}, {ret_type}, "{trap_escape(cc_name)}")'
        self.trap_generator.write_trap("types", trap)
        self.types_trap[tinfo_name] = type_id

        for index, arg in enumerate(funcdata):
            arg_type_id = self.write_type(arg.type)
            arg_trap = f"func_type_args({type_id}, {index}, {arg_type_id})"
            self.trap_generator.write_trap("types", arg_trap)

        return type_id

    def as_codeql_type(self, tinfo: ida_typeinf.tinfo_t) -> int:
        real = cast(int, tinfo.get_realtype())
        if real in types_map:
            return types_map[real]
        # Strip const/volatile modifier bits (TYPE_MODIF_MASK) and retry
        without_modifiers = real & ~ida_typeinf.TYPE_MODIF_MASK
        if without_modifiers in types_map:
            return types_map[without_modifiers]
        # Bool size variants (_BOOL2/_BOOL4/_BOOL8) — all map to bool
        if tinfo.is_bool():
            return types_map[ida_typeinf.BTF_BOOL]
        # Bitfield — map to underlying integer storage size
        if tinfo.is_bitfield():
            size_code = (real >> 4) & 0x03  # 0=__int8, 1=__int16, 2=__int32, 3=__int64
            return (3, 8, 11, 14)[size_code]
        self.logger.warning(f"Unknown BTF type {real} for tinfo {tinfo}")
        return 0
