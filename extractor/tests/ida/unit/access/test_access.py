from pathlib import Path
from pprint import pprint

import pytest
from conftest import parametrize_binary
from utils.helpers import get_src_dir, ida_at_least, run_codeql_query


def _default_cc(arch: str) -> str:
    """IDA's database-default calling convention, used for vtable function pointers."""
    return "__cdecl" if arch == "x86_32" else "__fastcall"


@parametrize_binary("compiled_extracted_binary", ["access_pointerfieldaccess"])
def test_VariableAccess(compiled_extracted_binary, arch, ida_version):
    """
    Test VariableAccess are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from VariableAccess va, Type t
    where
        va.getTarget().getType() = t and
        va.getEnclosingFunction().getName() = "main"
    select va.getTarget().getName(), t
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    # ppc reorders rows and scalarises the locals -> match by name, not position
    by_name = dict(matrix)
    assert "v3" in by_name, "the returned Animal* local (`v3`) is accessed"
    assert "dog" in by_name, "the on-stack Animal (`dog`) is accessed"

    if ida_at_least(ida_version, "9.4") and arch in ("x86_32", "x86_64", "arm32"):
        # IDA 9.4+ degrades the on-stack struct to a raw word array
        assert by_name["dog"].startswith(("_DWORD[", "_QWORD["))
    else:
        assert by_name["dog"] == "StructureType Animal"

    # arm32 and ppc leave `v3` a scalar instead of `Animal *`
    if arch not in ("arm32", "ppc32", "ppc64"):
        assert by_name["v3"] == "*StructureType Animal"


@parametrize_binary("compiled_extracted_binary", ["access_pointerfieldaccess"])
def test_FieldAccess_Struct(compiled_extracted_binary, arch, ida_version):
    """
    Test FieldAccess on a Struct are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from FieldAccess fa
    select fa, fa.getEA()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    name_dot = "DotFieldAccess: Field *const char name of StructureType Animal"
    name_arrow = "PointerFieldAccess: Field *const char name of StructureType Animal"
    vtable_dot = "DotFieldAccess: Field *ConstType vtable of StructureType Animal"
    vtable_arrow = "PointerFieldAccess: Field *ConstType vtable of StructureType Animal"
    speak_arrow = (
        f"PointerFieldAccess: Field **StructureType Animal {_default_cc(arch)} (*)(*StructureType Animal) "
        "speak of StructureType AnimalVTable"
    )
    rename_dot = (
        f"DotFieldAccess: Field **StructureType Animal {_default_cc(arch)} "
        "(*)(*StructureType Animal, *const char) rename of StructureType AnimalVTable"
    )
    rename_arrow = (
        f"PointerFieldAccess: Field **StructureType Animal {_default_cc(arch)} "
        "(*)(*StructureType Animal, *const char) rename of StructureType AnimalVTable"
    )
    if arch == "arm64":
        # dog.vtable->rename(...) is constant-propagated to the known global vtable
        # (dot), while result->vtable->speak(...) goes through an unknown runtime
        # pointer (arrow); rename itself never emits a separate field access here.
        assert matrix[0][0] == name_arrow
        assert matrix[1][0] == name_arrow
        assert matrix[2][0] == name_dot
        assert matrix[3][0] == vtable_dot
        assert matrix[4][0] == speak_arrow
        assert matrix[5][0] == vtable_arrow
    elif arch == "arm32":
        if ida_at_least(ida_version, "9.4"):
            # IDA 9.4+ scatter analysis on arm32 folds every access into arrows
            assert matrix[0][0] == name_arrow
            assert matrix[1][0] == name_arrow
            assert matrix[2][0] == rename_arrow
            assert matrix[3][0] == speak_arrow
            assert matrix[4][0] == vtable_arrow
        else:
            assert matrix[0][0] == name_arrow
            assert matrix[1][0] == name_arrow
    elif arch in ("x86_32", "x86_64"):
        assert matrix[0][0] == name_arrow
        assert matrix[1][0] == name_arrow
        if ida_at_least(ida_version, "9.4"):
            # IDA 9.4+ scatter analysis removes one cot_memref(name) access; vtable shifts up
            assert matrix[2][0] == rename_dot
            assert matrix[3][0] == speak_arrow
            assert matrix[4][0] == vtable_arrow
        else:
            assert matrix[2][0] == name_dot
            assert matrix[3][0] == vtable_dot
            assert matrix[4][0] == rename_dot
            assert matrix[5][0] == speak_arrow
            assert matrix[6][0] == vtable_arrow
    else:
        # ppc/mips/riscv: order and dot-vs-arrow vary -> check the field set, not positions
        descs = {row[0].split(": ", 1)[1] for row in matrix}
        assert "Field *const char name of StructureType Animal" in descs
        if arch in ("mips32", "mips64", "riscv64"):
            assert "Field *ConstType vtable of StructureType Animal" in descs
            assert any("speak of StructureType AnimalVTable" in d for d in descs)
        elif arch == "ppc32":
            # ppc32 folds the name/vtable dot reads away, keeps a partial `rename` access
            assert any("rename of StructureType AnimalVTable" in d for d in descs)
        # ppc64 does not expand the indirect dispatch: only the two `->name` arrows


@parametrize_binary("compiled_extracted_binary", ["access_dotfieldaccess_union"])
def test_FieldAccess_Union(compiled_extracted_binary, arch, ida_version):
    """
    Test DotFieldAccess on a Union are extracted correctly.
    """

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from DotFieldAccess dfa
    select dfa
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)

    assert matrix[0][0] == "DotFieldAccess: Field int i of UnionType Data"
    assert matrix[1][0] == "DotFieldAccess: Field int i of UnionType Data"
    assert matrix[2][0] == "DotFieldAccess: Field int i of UnionType Data"


@parametrize_binary("compiled_extracted_binary", ["access_dotfieldaccess"])
def test_DotFieldAccess_Uniq(compiled_extracted_binary, arch, ida_version):
    """
    Test DotFieldAccess on single layer are extracted correctly.
    """

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from DotFieldAccess dfa
    select dfa
    """

    if arch == "arm32":
        pytest.xfail("IDA does not emit DotFieldAccess on arm32")
    if arch in ("ppc32", "ppc64"):
        # ppc folds `rex.name`/`rex.age` into a whole-struct copy -- no field-access node
        pytest.xfail("IDA folds the single-layer field reads into a struct copy on ppc")
    if ida_at_least(ida_version, "9.4"):
        # IDA 9.4+ scatter analysis scalarises the stack struct (all arches); needs a non-scatterable fixture
        pytest.xfail("IDA 9.4+ scalarises the stack struct; no DotFieldAccess emitted")
    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert (
        matrix[0][0] == "DotFieldAccess: Field *const char name of StructureType Animal"
    )
    assert matrix[1][0] == "DotFieldAccess: Field int age of StructureType Animal"


@parametrize_binary("compiled_extracted_binary", ["access_dotfieldaccess_nested"])
def test_DotFieldAccess_Nested(compiled_extracted_binary, arch, ida_version):
    """
    Test DotFieldAccess nested, on multiple layer are extracted correctly.
    """

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from DotFieldAccess dfa
    select dfa
    """

    if ida_at_least(ida_version, "9.4"):
        # IDA 9.4+ scatter analysis scalarises both nested structs (all arches); needs a non-scatterable fixture
        pytest.xfail(
            "IDA 9.4+ scalarises the nested structs; no DotFieldAccess emitted"
        )

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    name_animal = "DotFieldAccess: Field *const char name of StructureType Animal"
    name_master = "DotFieldAccess: Field *const char name of StructureType Master"
    age_animal = "DotFieldAccess: Field int age of StructureType Animal"
    age_master = "DotFieldAccess: Field int age of StructureType Master"
    master = "DotFieldAccess: Field StructureType Master master of StructureType Animal"
    if arch == "x86_32":
        assert matrix[0][0] == name_master
        assert matrix[1][0] == age_master
        assert matrix[2][0] == name_animal
        assert matrix[3][0] == name_master
        assert matrix[4][0] == master
        assert matrix[5][0] == age_master
        assert matrix[6][0] == master
        assert matrix[7][0] == age_animal
        assert matrix[8][0] == name_master
        assert matrix[9][0] == master
        assert matrix[10][0] == age_animal
    elif arch == "arm32":
        assert matrix[0][0] == name_animal
        assert matrix[1][0] == master
        assert matrix[2][0] == age_animal
        assert matrix[3][0] == name_master
        assert matrix[4][0] == master
        assert matrix[5][0] == age_animal
    elif arch in ("ppc32", "ppc64", "mips32", "mips64"):
        # order and count vary by ISA -> assert the nested-field set, not positions
        descs = {row[0] for row in matrix}
        core = {name_animal, name_master, age_animal, master}
        assert core <= descs, f"missing nested DotFieldAccess: {core - descs}"
        if arch in ("mips32", "mips64"):
            assert age_master in descs
        # ppc folds the `Master.age` read away, so `age_master` is absent there
    else:
        assert matrix[0][0] == name_master
        assert matrix[1][0] == age_master
        assert matrix[2][0] == name_animal
        assert matrix[3][0] == name_master
        assert matrix[4][0] == master
        assert matrix[5][0] == age_master
        assert matrix[6][0] == master
        assert matrix[7][0] == age_master
        assert matrix[8][0] == age_animal
        assert matrix[9][0] == name_master
        assert matrix[10][0] == master
        assert matrix[11][0] == age_animal


@parametrize_binary("compiled_extracted_binary", ["access_pointerfieldaccess"])
def test_PointerFieldAccess(compiled_extracted_binary, arch, ida_version):
    """
    Test PointerFieldAccess are correctly extracted.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from PointerFieldAccess pfa
    select pfa
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    name_arrow = "PointerFieldAccess: Field *const char name of StructureType Animal"
    vtable_arrow = "PointerFieldAccess: Field *ConstType vtable of StructureType Animal"
    speak_arrow = (
        f"PointerFieldAccess: Field **StructureType Animal {_default_cc(arch)} (*)(*StructureType Animal) "
        "speak of StructureType AnimalVTable"
    )
    rename_arrow = (
        f"PointerFieldAccess: Field **StructureType Animal {_default_cc(arch)} "
        "(*)(*StructureType Animal, *const char) rename of StructureType AnimalVTable"
    )
    if arch == "arm32" and ida_at_least(ida_version, "9.4"):
        # IDA 9.4+ scatter analysis on arm32 folds every access into arrows
        assert matrix[0][0] == name_arrow
        assert matrix[1][0] == name_arrow
        assert matrix[2][0] == rename_arrow
        assert matrix[3][0] == speak_arrow
        assert matrix[4][0] == vtable_arrow
    elif arch == "arm32":
        assert matrix[0][0] == name_arrow
        assert matrix[1][0] == name_arrow
    else:
        assert matrix[0][0] == name_arrow
        assert matrix[1][0] == name_arrow
        if arch in ("ppc32", "ppc64"):
            # ppc leaves the indirect dispatch unexpanded -> only the two `->name` arrows
            assert len(matrix) == 2
        else:
            assert matrix[2][0] == speak_arrow
            assert matrix[3][0] == vtable_arrow
