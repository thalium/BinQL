from pathlib import Path
from pprint import pprint

import pytest
from conftest import parametrize_binary
from utils.helpers import get_src_dir, run_codeql_query


@parametrize_binary("compiled_extracted_binary", ["function_param"])
def test_Function_Parameters(compiled_extracted_binary, arch, ida_version):
    """
    Test parameters of main are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from Parameter p
    where
        p.getFunction().hasName("main")
    select p.getType(), p.getName()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0] == ["int", "argc"]
    assert matrix[1] == ["**const char", "argv"]
    assert matrix[2] == ["**const char", "envp"]


@parametrize_binary("compiled_extracted_binary", ["function_call"])
def test_Function_FunctionCall_List(compiled_extracted_binary, arch, ida_version):
    """
    Test that calls are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from FunctionCall fc
    // filter to reduce output
    where
        fc.getEnclosingFunction().getName() = "main"
    select fc
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "FunctionCall to Function foo"


@parametrize_binary("compiled_extracted_binary", ["function_call"])
def test_Function_FunctionToFunctionCall(compiled_extracted_binary, arch, ida_version):
    """
    Test that calls targeting a specific function are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from Function f
    where
        f.getName() = "foo"
    select f.getACallToThisFunction()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "FunctionCall to Function foo"


@parametrize_binary("compiled_extracted_binary", ["function_sizeof"])
def test_Function_Sizeof(compiled_extracted_binary, arch, ida_version):
    """
    Test sizeof are extracted correctly.
    """
    if arch in ("ppc32", "ppc64"):
        pytest.xfail(
            "Hex-Rays folds sizeof to a constant on ppc (no SizeofExprOperator node)"
        )

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from SizeofExprOperator s
    select s
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "SizeofExprOperator to LocalVariableAccess: my_struct"
