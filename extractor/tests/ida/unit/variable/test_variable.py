from pathlib import Path
from pprint import pprint

from conftest import parametrize_binary
from utils.helpers import get_src_dir, run_codeql_query


@parametrize_binary("compiled_extracted_binary", ["variable_local"])
def test_Variable_Local(compiled_extracted_binary, arch, ida_version):
    """
    Test LocalVariable of main are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from LocalVariable lv
    where lv.getFunction().getName() = "main"
    select lv.getName(), lv.getAnAccess().getName()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    for i, entry in enumerate(matrix):
        assert entry[0] == entry[1], (
            f"Row {i}: name {entry[0]!r} != access {entry[1]!r}"
        )


@parametrize_binary("compiled_extracted_binary", ["variable_global"])
def test_Variable_Global(compiled_extracted_binary, arch, ida_version):
    """
    Test GlobalVariable are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from GlobalVariable gl
    select gl.getName(), gl.getAnAccess().getName()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    for i, entry in enumerate(matrix):
        assert entry[0] == entry[1], (
            f"Row {i}: name {entry[0]!r} != access {entry[1]!r}"
        )


@parametrize_binary("compiled_extracted_binary", ["variable_param"])
def test_Variable_Parameter(compiled_extracted_binary, arch, ida_version):
    """
    Test Parameter variables of functions are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from Parameter p
    where p.getFunction().getName() = "binql_sum"
    select p.getName(), p.getAnAccess().getName()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    for i, entry in enumerate(matrix):
        assert entry[0] == entry[1], (
            f"Row {i}: name {entry[0]!r} != access {entry[1]!r}"
        )
