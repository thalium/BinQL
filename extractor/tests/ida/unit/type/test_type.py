from pathlib import Path
from pprint import pprint

from conftest import parametrize_binary
from utils.helpers import get_src_dir, run_codeql_query


@parametrize_binary("compiled_extracted_binary", ["type_struct"])
def test_Struct(compiled_extracted_binary, arch, ida_version):
    """
    Test Structures are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from StructureType s
    select s
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "StructureType Animal"


@parametrize_binary("compiled_extracted_binary", ["type_union"])
def test_Union(compiled_extracted_binary, arch, ida_version):
    """
    Test Unions are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from UnionType u
    select u
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "UnionType Data"


@parametrize_binary("compiled_extracted_binary", ["type_enum"])
def test_Enum_Enum(compiled_extracted_binary, arch, ida_version):
    """
    Test Enums are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from Enum e
    select e
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "Enum AnimalType"


@parametrize_binary("compiled_extracted_binary", ["type_enum"])
def test_Enum_EnumConstant(compiled_extracted_binary, arch, ida_version):
    """
    Test EnumConstant are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from Enum e
    select e.getAnEnumConstant()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "EnumConstant AnimalType::DOG"
    assert matrix[1][0] == "EnumConstant AnimalType::CAT"
    assert matrix[2][0] == "EnumConstant AnimalType::BIRD"


@parametrize_binary("compiled_extracted_binary", ["type_enum"])
def test_Enum_EnumConstantAccess(compiled_extracted_binary, arch, ida_version):
    """
    Test EnumConstantAccess are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from Enum e
    select e.getAnEnumConstant().getAnAccess()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "EnumConstantAccess: AnimalType::DOG"
