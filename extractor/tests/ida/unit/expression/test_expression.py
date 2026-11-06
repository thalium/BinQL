from pathlib import Path
from pprint import pprint

import pytest
from conftest import parametrize_binary
from utils.helpers import get_src_dir, ida_at_least, run_codeql_query


@parametrize_binary("compiled_extracted_binary", ["expression_assign"])
def test_Expression_Assign(compiled_extracted_binary, arch, ida_version):
    """
    Test AssignExpr of main are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from AssignExpr ae
    where ae.getEnclosingFunction().getName() = "main"
    select ae.getAPrimaryQlClass()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "AssignExpr"


@parametrize_binary("compiled_extracted_binary", ["expression_ptrderef"])
def test_Expression_PtrDeref(compiled_extracted_binary, arch, ida_version):
    """
    Test PointerDereferenceExpr of main are extracted correctly.
    """
    if arch in ("ppc32", "ppc64", "mips32", "mips64"):
        pytest.xfail(
            "IDA lowers *(p+1) without a PointerDereferenceExpr node on ppc/mips"
        )

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from PointerDereferenceExpr ptrd
    select ptrd, ptrd.getChild(0)
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    # CStyleCast / PointerDereferenceExpr toString now append " of <operand>"
    # (qlpack commit 7828d57), so match the operand column exactly and only
    # prefix-check the deref column.
    if arch == "x86_32":
        expected_child = (
            "CStyleCast to int (**)(void) of (ParameterVariableAccess: a1) "
            "- (PositiveIntNumberLiteral: 16 (0x10))"
        )
    elif arch == "arm32" and not ida_at_least(ida_version, "9.5"):
        # IDA 9.5+ recovers `p` on arm32 like the other arches
        expected_child = "(AddressOfExpr) + (PositiveIntNumberLiteral: 32518 (0x7f06))"
    else:
        expected_child = (
            "(CStyleCast to _DWORD * of LocalVariableAccess: p) "
            "+ (PositiveIntNumberLiteral: 1 (0x1))"
        )
    assert matrix[0][0].startswith("PointerDereferenceExpr"), (
        "Expected a PointerDereferenceExpr row"
    )
    assert matrix[0][1] == expected_child, (
        f"Expected PointerDereferenceExpr on {expected_child!r}"
    )


@parametrize_binary("compiled_extracted_binary", ["expression_array"])
def test_ArrayExpr(compiled_extracted_binary, arch, ida_version):
    """
    Test buffer accesses are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from ArrayExpr ae
    select ae
    """
    if ida_at_least(ida_version, "9.4"):
        # IDA 9.4+ scatter analysis folds the fixed-index `arr[i]` to scalars (all arches); needs a non-scatterable fixture
        pytest.xfail("IDA 9.4+ scalarises the fixed-index array; no ArrayExpr emitted")
    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0] == [
        "ArrayExpr: LocalVariableAccess: arr[PositiveIntNumberLiteral: 0 (0x0)]"
    ]
