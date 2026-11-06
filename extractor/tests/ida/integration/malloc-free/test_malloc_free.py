from pathlib import Path
from pprint import pprint

from conftest import parametrize_binary
from utils.helpers import get_src_dir, run_codeql_query


@parametrize_binary("compiled_extracted_binary", ["malloc_free"])
def test_FunctionCall(compiled_extracted_binary, arch, ida_version):
    """
    Test that function calls and their arguments in `main` are correctly identified.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from FunctionCall fc
    where fc.getEnclosingFunction().getName() = "main"
    select fc.getName() as fname, fc.getAChild() as cname
    order by fname, cname
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)

    if arch in ("ppc32", "ppc64") or (
        arch == "riscv64" and ida_version in ("9.0", "9.1")
    ):
        ptr = "LocalVariableAccess: v4"
    else:
        ptr = "LocalVariableAccess: ptr"

    # ppc/mips leave the call as an unresolved PLT thunk; name still contains the symbol
    assert "free" in matrix[0][0]
    assert matrix[0][1] == ptr
    assert "malloc" in matrix[1][0]
    assert matrix[1][1] == "PositiveIntNumberLiteral: 10 (0xa)"
    assert "printf" in matrix[2][0]
    assert matrix[2][1] == ptr
    assert "printf" in matrix[3][0]
    assert matrix[3][1] == "StringLiteral Variable: %p"


@parametrize_binary("compiled_extracted_binary", ["malloc_free"])
def test_DisplayLines(compiled_extracted_binary, arch, ida_version):
    """
    Ordering and content of lines in `main`.

    Imply ExpressionStmt, ReturnStmt
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from Node n, ExpressionStmt es, ReturnStmt r
    where n.getEnclosingFunction().getName() = "main" and
        (
        n.getKind() = es.getKind() or
        n.getKind() = r.getKind()
        )
    select n.getLocation().getStart() as nloc, n
    order by nloc
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)

    if arch in ("ppc32", "ppc64") or (
        arch == "riscv64" and ida_version in ("9.0", "9.1")
    ):
        ptr = "v4"
    else:
        ptr = "ptr"

    assert matrix[0][1].startswith("ExpressionStmt FunctionCall to Function ")
    assert "printf" in matrix[0][1]
    assert matrix[1][1].startswith(
        f"ExpressionStmt AssignExpr: LocalVariableAccess: {ptr} and FunctionCall to Function "
    )
    assert "malloc" in matrix[1][1]
    assert matrix[2][1].startswith("ExpressionStmt FunctionCall to Function ")
    assert "free" in matrix[2][1]
    assert matrix[3][1] == "Return PositiveIntNumberLiteral: 0 (0x0)"


@parametrize_binary("compiled_extracted_binary", ["malloc_free"])
def test_TrackVariable(compiled_extracted_binary, arch, ida_version):
    """
    Test tracking of a local variable allocated by malloc and freed by free.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    # `%malloc%` / `%free%` also match the ppc/mips thunk names (`ext_malloc`, `_…free@@GLIBC`)
    query = """
    import binary
    from FunctionCall mallocCall, FunctionCall freeCall, LocalVariable var, AssignExpr assign
    where
    // malloc call assigned to a local variable
    mallocCall.getName().matches("%malloc%") and
    assign.getRightChild() = mallocCall and
    assign.getLeftChild().(LocalVariableAccess).getVariable() = var and
    // free call frees the same variable
    freeCall.getName().matches("%free%") and
    exists(LocalVariableAccess freeAccess |
        freeCall.getArgument(0) = freeAccess and
        freeAccess.getVariable() = var
    ) and
    // both inside main
    mallocCall.getEnclosingFunction().getName() = "main" and
    freeCall.getEnclosingFunction() = mallocCall.getEnclosingFunction()
    select mallocCall, freeCall, assign, var, var.getType()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert len(matrix) == 1
    malloc_call, free_call, asg, var, var_type = matrix[0]

    if arch in ("ppc32", "ppc64") or (
        arch == "riscv64" and ida_version in ("9.0", "9.1")
    ):
        ptr = "v4"
    else:
        ptr = "ptr"

    assert "malloc" in malloc_call
    assert "free" in free_call
    assert asg.startswith(
        f"AssignExpr: LocalVariableAccess: {ptr} and FunctionCall to Function "
    )
    assert "malloc" in asg
    assert var == f"LocalVariable *void {ptr} in Function main"
    assert var_type == "*void"


@parametrize_binary("compiled_extracted_binary", ["malloc_free"])
def test_SearchString(compiled_extracted_binary, arch, ida_version):
    """
    Test that specific string literals are found in `main`.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from StringLiteral s
    where
    s.getEnclosingFunction().getName() = "main" and
    s.getString().matches("%Variable%")
    select s.getString()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "Variable: %p"


@parametrize_binary("compiled_extracted_binary", ["malloc_free"])
def test_IsImmediateReturned(compiled_extracted_binary, arch, ida_version):
    """
    Test detection of immediate return values in `main`.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from Function f, ReturnStmt r
    where
    f.getName() = "main" and
    r.getEnclosingFunction() = f and
    exists(PositiveIntNumberLiteral lit | r.getTarget() = lit)
    select f, r.getTarget(), "This return is immediate (integer literal)."
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0] == [
        "Function main",
        "PositiveIntNumberLiteral: 0 (0x0)",
        "This return is immediate (integer literal).",
    ]


@parametrize_binary("compiled_extracted_binary", ["malloc_free"])
def test_IsDecompiled(compiled_extracted_binary, arch, ida_version):
    """
    Test that `main` is not an empty function in the decompiled pseudo-code.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    predicate isEmptyFunc(Function f) {
        f.getName() = "main" and
        exists(Statement s |
            s = f.getBlock().getChild(0) and
            not s instanceof EmptyStmt
        )
    }
    from Function f
    where isEmptyFunc(f)
    select f, "Not a function without pseudo-code"
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0] == ["Function main", "Not a function without pseudo-code"]
