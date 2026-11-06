from pathlib import Path
from pprint import pprint

import pytest
from conftest import parametrize_binary
from utils.helpers import get_src_dir, ida_at_least, run_codeql_query


@parametrize_binary("compiled_extracted_binary", ["stmt_asm"])
def test_AsmStmt(compiled_extracted_binary, arch, ida_version):
    """
    Test AsmStmt are extracted correctly: one block in `asm_one`, two in `asm_two`.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    select
        count(AsmStmt a | a.getEnclosingFunction().getName() = "asm_one"),
        count(AsmStmt a | a.getEnclosingFunction().getName() = "asm_two")
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0] == ["1", "2"], "Expected 1 AsmStmt in `asm_one`, 2 in `asm_two`"


# Per arch: blocks of (ea, mnemonic, text) IDA 9.0-9.4 show them
ASM_EXPECTED = {
    "x86_32": (
        [[(0x118A, "fninit", "fninit"), (0x118C, "fnclex", "fnclex")]],
        [
            [(0x119E, "fninit", "fninit"), (0x11A0, "fnclex", "fnclex")],
            [(0x11AC, "invd", "invd")],
        ],
    ),
    "x86_64": (
        [[(0x112D, "fninit", "fninit"), (0x112F, "fnclex", "fnclex")]],
        [
            [(0x1138, "fninit", "fninit"), (0x113A, "fnclex", "fnclex")],
            [(0x1146, "invd", "invd")],
        ],
    ),
    "arm32": (
        [[(0x544, "LDC", "LDC p14, c5, [R0]"), (0x548, "STC", "STC p14, c5, [R0]")]],
        [
            [
                (0x564, "LDC", "LDC p14, c5, [R0]"),
                (0x568, "STC", "STC p14, c5, [R0]"),
            ],
            [(0x57C, "LDC", "LDC p14, c6, [R0]")],
        ],
    ),
    "arm64": (
        [[(0x768, "MSR", "MSR DAIFSet, #2"), (0x76C, "MSR", "MSR DAIFClr, #2")]],
        [
            [(0x778, "MSR", "MSR DAIFSet, #2"), (0x77C, "MSR", "MSR DAIFClr, #2")],
            [(0x790, "HVC", "HVC #0")],
        ],
    ),
    "ppc32": (
        [[(0x5C0, "eieio", "eieio"), (0x5C4, "tlbsync", "tlbsync")]],
        [
            [(0x604, "eieio", "eieio"), (0x608, "tlbsync", "tlbsync")],
            [(0x618, "tlbsync", "tlbsync")],
        ],
    ),
    "ppc64": (
        [[(0x920, "eieio", "eieio"), (0x924, "tlbsync", "tlbsync")]],
        [
            [(0x950, "eieio", "eieio"), (0x954, "tlbsync", "tlbsync")],
            [(0x968, "tlbsync", "tlbsync")],
        ],
    ),
    "mips32": (
        [[(0x73C, "tlbwi", "tlbwi"), (0x740, "tlbr", "tlbr")]],
        [
            [(0x774, "tlbwi", "tlbwi"), (0x778, "tlbr", "tlbr")],
            [(0x788, "tlbp", "tlbp")],
        ],
    ),
    "mips64": (
        [[(0xB0C, "tlbwi", "tlbwi"), (0xB10, "tlbr", "tlbr")]],
        [
            [(0xB44, "tlbwi", "tlbwi"), (0xB48, "tlbr", "tlbr")],
            [(0xB58, "tlbp", "tlbp")],
        ],
    ),
    "riscv64": (
        [[(0x63E, "fence.i", "fence.i"), (0x642, "ecall", "ecall")]],
        [
            [(0x658, "fence.i", "fence.i"), (0x65C, "ecall", "ecall")],
            [(0x66C, "fence.i", "fence.i")],
        ],
    ),
}


@parametrize_binary("compiled_extracted_binary", ["stmt_asm"])
def test_AsmStmt_Instructions(compiled_extracted_binary, arch, ida_version):
    """
    Test each AsmStmt carries its own instructions, in `casm` order.

    `asm_two` holds two blocks, so instructions leaking across blocks would show.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from AsmStmt a, AsmInstruction ins, string fn
    where fn = a.getEnclosingFunction().getName()
        and fn in ["asm_one", "asm_two"]
        and ins = a.getAnInstruction()
    select fn, a.getInstruction(0).getEA(), a.getNumberOfInstructions(),
        ins.getIndex(), ins.getEA(), ins.getMnemonic(), ins.getText()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)

    blocks: dict[str, dict[int, list]] = {"asm_one": {}, "asm_two": {}}
    for fn, first_ea, n_insns, index, ea, mnemonic, text in matrix:
        block = blocks[fn].setdefault(int(first_ea, 16), [int(n_insns)])
        block.append((int(index), int(ea, 16), mnemonic, " ".join(text.split())))

    actual = []
    for fn in ("asm_one", "asm_two"):
        fn_blocks = []
        for _, (n_insns, *insns) in sorted(blocks[fn].items()):
            insns.sort()
            assert [i[0] for i in insns] == list(range(n_insns)), (
                f"Expected indices 0..{n_insns - 1} in a block of `{fn}`"
            )
            fn_blocks.append([i[1:] for i in insns])
        actual.append(fn_blocks)

    expected_blocks = ASM_EXPECTED[arch]
    if arch in ("ppc32", "ppc64") and ida_at_least(ida_version, "9.5"):
        # IDA 9.5+ lifts `eieio` out of the asm block into an `__eieio()` intrinsic call
        expected_blocks = tuple(
            [[insn for insn in block if insn[1] != "eieio"] for block in fn_blocks]
            for fn_blocks in expected_blocks
        )
    assert tuple(actual) == expected_blocks, (
        "Expected the asm blocks' instructions as IDA shows them"
    )

    query = """
    import binary
    from AsmStmt a, string fn
    where fn = a.getEnclosingFunction().getName() and fn in ["asm_one", "asm_two"]
    select fn, a.getInstruction(0).getEA(), a.display()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)

    displayed = tuple(
        [d for _, _, d in sorted(r for r in matrix if r[0] == fn)]
        for fn in ("asm_one", "asm_two")
    )
    expected = tuple(
        ["__asm { " + "; ".join(t for _, _, t in block) + " }" for block in fn_blocks]
        for fn_blocks in expected_blocks
    )
    assert displayed == expected, "Expected `__asm { insn; insn }` from display()"


@parametrize_binary("compiled_extracted_binary", ["stmt_block"])
def test_BlockStmt(compiled_extracted_binary, arch, ida_version):
    """
    Test BlockStmt are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    select count(
    BlockStmt bs |
        exists(Function f |
            f.getName() = "main" and
            bs = f.getBlock()
        )
    )
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "1", "Expected 1 BlockStmt in `foo` function: `{}`"


def test_BreakStmt(arch, ida_version):
    """
    Test BreakStmt are extracted correctly.
    """
    pytest.xfail("No binary make IDA emit break switch.")


def test_ContinueStmt(arch, ida_version):
    """
    Test ContinueStmt are extracted correctly.
    """
    pytest.xfail("No binary make IDA emit continue switch.")


@parametrize_binary("compiled_extracted_binary", ["stmt_do"])
def test_DoStmt(compiled_extracted_binary, arch, ida_version):
    """
    Test DoStmt are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    select count(DoStmt ds)
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "1", "Expected 1 EmptyBlock in `foo` function: `{;}`"


@parametrize_binary("compiled_extracted_binary", ["stmt_empty"])
def test_EmptyStmt(compiled_extracted_binary, arch, ida_version):
    """
    Test EmptyStmt are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    select count(
    EmptyStmt es |
        exists(Function f |
            f.getName() = "foo" and
            es = f.getBlock().getChild(0)
        )
    )
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "1", "Expected 1 EmptyBlock in `foo` function: `{;}`"


@parametrize_binary("compiled_extracted_binary", ["stmt_expression"])
def test_ExpressionStmt(compiled_extracted_binary, arch, ida_version):
    """
    Test ExpressionStmt are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    select count(
    ExpressionStmt es |
        exists(Function f |
            f.getName() = "main" and
            es = f.getBlock().getChild(0)
        )
    )
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "1", "Expected 1 ExpressionStmt in `main` function: `{...;}`"


@parametrize_binary("compiled_extracted_binary", ["stmt_for"])
def test_ForStmt(compiled_extracted_binary, arch, ida_version):
    """
    Test ForStmt are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from ForStmt fs
    select fs, fs.getInitialization().getAPrimaryQlClass(), fs.getCondition(), fs.getUpdate(), fs.getStmt(), fs.getAnIterationVariable().getName()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "ForStmt", "Expected ForStmt"
    assert matrix[0][1] == "AssignExpr", "Expected as initializer of ForStmt"
    # mips keeps `i < 10`; the other arches normalise it to `i <= 9`
    if arch in ("mips32", "mips64"):
        expected_for_cond = (
            "(LocalVariableAccess: i) < (PositiveIntNumberLiteral: 10 (0xa))"
        )
    else:
        expected_for_cond = (
            "(LocalVariableAccess: i) <= (PositiveIntNumberLiteral: 9 (0x9))"
        )
    assert matrix[0][2] == expected_for_cond, "Expected as condition of ForStmt"
    assert matrix[0][3] == "PrefixIncrementOperation", "Expected as updater of ForStmt"
    assert matrix[0][4] == "BlockStmt", "Expected as statement of ForStmt"
    assert matrix[0][5] == "i", "Expected as iteration variable of ForStmt"


@parametrize_binary("compiled_extracted_binary", ["stmt_goto"])
def test_Stmt_Goto(compiled_extracted_binary, arch, ida_version):
    """
    Test GotoStmt are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from GotoStmt gs
    select gs.getName()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "label_e", "Expected label_e as Goto label name"
    assert matrix[1][0] == "label_a", "Expected label_a as Goto label name"
    assert matrix[2][0] == "label_g", "Expected label_g as Goto label name"


@parametrize_binary("compiled_extracted_binary", ["stmt_goto"])
def test_Stmt_Goto_LabelLinking(compiled_extracted_binary, arch, ida_version):
    """
    Test GotoStmt are correctly linked to LabelStmt.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from GotoStmt gs, LabelStmt ls
    where gs.getLabel().getNode().getEA() = ls.getNode().getEA()
    select gs.getName()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "label_e", "Expected label_e as Goto label name"
    assert matrix[1][0] == "label_a", "Expected label_a as Goto label name"
    assert matrix[2][0] == "label_g", "Expected label_g as Goto label name"


@parametrize_binary("compiled_extracted_binary", ["stmt_goto"])
def test_LabelStmt(compiled_extracted_binary, arch, ida_version):
    """
    Test LabelStmt are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from LabelStmt ls
    select ls
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    for i in range(2):
        assert matrix[i][0] == "Label", "Expected Label"


@parametrize_binary("compiled_extracted_binary", ["stmt_if"])
def test_IfStmt(compiled_extracted_binary, arch, ida_version):
    """
    Test IfStmt are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from IfStmt is
    where
        is.getEnclosingFunction().getName() = "main"
    select is, is.getCondition(), is.getThen(), is.getElse()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "IfStmt", "Expected IfStmt"

    # IDA-9.4+'s Hex-Rays adds an explicit `!= 0`; x86 and arm64 also fold the
    # array to a scalar, the other arches keep the ArrayExpr. Pre-9.4: bare ArrayExpr.
    expected_ifstmt_condition = dict.fromkeys(
        ("x86_32", "x86_64", "arm64"),
        "(LocalVariableAccess: v5) != (PositiveIntNumberLiteral: 0 (0x0))",
    ) | {
        a: (
            f"(ArrayExpr: LocalVariableAccess: {arr}[PositiveIntNumberLiteral: 3 (0x3)]) "
            "!= (PositiveIntNumberLiteral: 0 (0x0))"
        )
        # mips64 renames the array local `vars0` -> `v4` on 9.4
        for a, arr in (
            ("arm32", "vars0"),
            ("ppc32", "vars0"),
            ("ppc64", "vars0"),
            ("mips32", "vars0"),
            ("mips64", "v4"),
            ("riscv64", "vars0"),
        )
    }
    expected_condition = (
        expected_ifstmt_condition[arch]
        if ida_at_least(ida_version, "9.4")
        else "ArrayExpr: LocalVariableAccess: vars0[PositiveIntNumberLiteral: 3 (0x3)]"
    )
    assert matrix[0][1] == expected_condition, (
        "Expected `vars0[IDX]` as condition of IfStmt"
    )
    assert matrix[0][2] == "BlockStmt", "Expected as then of IfStmt"
    assert matrix[0][3] == "BlockStmt", "Expected as else of IfStmt"


@parametrize_binary("compiled_extracted_binary", ["stmt_return"])
def test_ReturnStmt(compiled_extracted_binary, arch, ida_version):
    """
    Test ReturnStmt are extracted correctly.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    select count(
    ReturnStmt rs |
        exists(Function f |
            f.getName() = "main" and
            rs = f.getBlock().getChild(0)
        )
    )
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "1", "Expected 1 ReturnStmt in `main` function: `{...;}`"


@parametrize_binary("compiled_extracted_binary", ["stmt_switch"])
def test_SwitchStmt_Alone(compiled_extracted_binary, arch, ida_version):
    """
    Test SwitchStmt are extracted correctly.
    """
    if arch == "arm64":
        pytest.xfail("IDA does not emit switch statements on ARM64.")
    if arch == "ppc32" and ida_version == "9.5":
        # IDA 9.5 (beta 2) no longer resolves the PIC jump table: `__asm { bctr# switch jump }`
        pytest.xfail("IDA 9.5 (beta 2) does not emit the switch statement on ppc32.")

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from SwitchStmt switch
    select switch.getControllingExpr(), switch.getNumberSwitches()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    # ppc/mips/riscv keep the `getValue()` call as the controlling expr, like
    # x86_32/arm32; only x86_64 on IDA 9.3+ folds it to a local.
    if arch in [
        "x86_64",
        "x86_32",
        "arm32",
        "ppc32",
        "ppc64",
        "mips32",
        "mips64",
        "riscv64",
    ]:
        if arch == "x86_64" and ida_version in ("9.3", "9.4"):
            assert matrix[0][0] == "LocalVariableAccess: v3", (
                "Expected LocalVariableAccess as condition on SwitchStmt on x86_64 (IDA 9.3+)"
            )
        else:
            assert matrix[0][0] == "FunctionCall to Function getValue", (
                "Expected FunctionCall as condition on SwitchStmt on x86_32/arm32/ppc/mips/riscv"
            )
    else:
        assert matrix[0][0] == "LocalVariableAccess: v3", (
            "Expected LocalVariableAccess as condition on SwitchStmt"
        )


@parametrize_binary("compiled_extracted_binary", ["stmt_switch"])
def test_SwitchStmt_SwitchCase(compiled_extracted_binary, arch, ida_version):
    """
    Test SwitchCase are extracted correctly.
    """
    if arch == "arm64":
        pytest.xfail("IDA does not emit switch statements on ARM64.")
    if arch == "ppc32" and ida_version == "9.5":
        # IDA 9.5 (beta 2) no longer resolves the PIC jump table: `__asm { bctr# switch jump }`
        pytest.xfail("IDA 9.5 (beta 2) does not emit the switch statement on ppc32.")

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from SwitchCase sc
    select sc.getChildNum(), sc
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    for i in range(7):
        assert matrix[i] == [str(i), "BlockStmt"]


@parametrize_binary("compiled_extracted_binary", ["stmt_switch"])
def test_SwitchStmt_SwitchCaseLinking(compiled_extracted_binary, arch, ida_version):
    """
    Test SwitchStmt are correctly linked to SwitchCase.
    """
    if arch == "arm64":
        pytest.xfail("IDA does not emit switch statements on ARM64.")
    if arch == "ppc32" and ida_version == "9.5":
        # IDA 9.5 (beta 2) no longer resolves the PIC jump table: `__asm { bctr# switch jump }`
        pytest.xfail("IDA 9.5 (beta 2) does not emit the switch statement on ppc32.")

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from SwitchCase sc
    select sc.getChildNum(), sc, sc.getPreviousSwitchCase().getChildNum(), sc.getNextSwitchCase().getChildNum()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    for i in range(1, 6):
        assert matrix[i - 1] == [str(i), "BlockStmt", str(i - 1), str(i + 1)]


@parametrize_binary("compiled_extracted_binary", ["stmt_switch"])
def test_SwitchCase_Values(compiled_extracted_binary, arch, ida_version):
    """
    Test SwitchCase values and `default` are extracted (cases 0, 1, 3..6 + default).
    """
    if arch == "arm64":
        pytest.xfail("IDA does not emit switch statements on ARM64.")
    if arch == "ppc32" and ida_version == "9.5":
        # IDA 9.5 (beta 2) no longer resolves the PIC jump table: `__asm { bctr# switch jump }`
        pytest.xfail("IDA 9.5 (beta 2) does not emit the switch statement on ppc32.")

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from SwitchStmt s
    select count(s.getASwitchCase()), count(SwitchCase sc | sc.isDefault()),
        concat(string v | v = s.getASwitchCase().getAValue() | v, "," order by v),
        count(s.getDefaultCase())
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix == [["7", "1", "0,1,3,4,5,6", "1"]], (
        "Expected 7 cases, one `default`, values {0, 1, 3, 4, 5, 6}"
    )


@parametrize_binary("compiled_extracted_binary", ["stmt_switch"])
def test_SwitchCase_ControllingExpr(compiled_extracted_binary, arch, ida_version):
    """
    Test the controlling expr is not a SwitchCase and the switch has 7 cases + 1 expr.
    """
    if arch == "arm64":
        pytest.xfail("IDA does not emit switch statements on ARM64.")
    if arch == "ppc32" and ida_version == "9.5":
        # IDA 9.5 (beta 2) no longer resolves the PIC jump table: `__asm { bctr# switch jump }`
        pytest.xfail("IDA 9.5 (beta 2) does not emit the switch statement on ppc32.")

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from SwitchStmt s
    select count(SwitchCase sc | sc = s.getControllingExpr()),
        count(s.getAChild()), s.getNumberSwitches()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix == [["0", "8", "7"]], (
        "Expected 7 cases + 1 controlling expr as children of SwitchStmt"
    )


@parametrize_binary("compiled_extracted_binary", ["stmt_switch_values"])
def test_SwitchCase_NegativeAndMerged(compiled_extracted_binary, arch, ida_version):
    """
    Test negative case values are signed and `case 1: case 2:` lands in one SwitchCase.
    """
    if arch == "arm64":
        pytest.xfail("IDA does not emit switch statements on ARM64.")
    if arch == "mips64" and ida_version in ("9.2", "9.3"):
        pytest.xfail("IDA 9.2/9.3 emits an if-chain instead of a switch on mips64.")
    if arch == "ppc32" and ida_version == "9.5":
        # IDA 9.5 (beta 2) no longer resolves the PIC jump table: `__asm { bctr# switch jump }`
        pytest.xfail("IDA 9.5 (beta 2) does not emit the switch statement on ppc32.")

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    # Order by string: unsigned 32-bit values overflow `toInt()`.
    query = """
    import binary
    from SwitchCase sc
    where not sc.isDefault()
    select concat(string v | v = sc.getAValue() | v, "," order by v)
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    # riscv64 on IDA < 9.3 types the controlling expr `unsigned int`, so the
    # negative cases are emitted (and printed by Hex-Rays) as 0xFFFFFFFD..F.
    if arch == "riscv64" and ida_version in ("9.0", "9.1", "9.2"):
        negatives = ["4294967293", "4294967294", "4294967295"]
    else:
        negatives = ["-3", "-2", "-1"]
    assert sorted(row[0] for row in matrix) == sorted([*negatives, "1,2", "4", "5"]), (
        f"Expected cases {negatives}, {{1, 2}}, 4, 5"
    )


@parametrize_binary("compiled_extracted_binary", ["stmt_switch_values"])
def test_SwitchCase_Default(compiled_extracted_binary, arch, ida_version):
    """
    Test exactly one `default`, with no value, on a switch with gaps (0 and 3).
    """
    if arch == "arm64":
        pytest.xfail("IDA does not emit switch statements on ARM64.")
    if arch == "mips64" and ida_version in ("9.2", "9.3"):
        pytest.xfail("IDA 9.2/9.3 emits an if-chain instead of a switch on mips64.")
    if arch == "ppc32" and ida_version == "9.5":
        # IDA 9.5 (beta 2) no longer resolves the PIC jump table: `__asm { bctr# switch jump }`
        pytest.xfail("IDA 9.5 (beta 2) does not emit the switch statement on ppc32.")

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from SwitchStmt s, SwitchCase d
    where d = s.getDefaultCase() and d.getSwitchStmt() = s
    select count(s.getASwitchCase()), count(d.getAValue())
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix == [["7", "0"]], "Expected 6 valued cases + 1 default"


@parametrize_binary("compiled_extracted_binary", ["stmt_while"])
def test_WhileStmt(compiled_extracted_binary, arch, ida_version):
    """
    Test WhileStmt are extracted correctly.
    """
    if arch in ("mips32", "mips64"):
        pytest.xfail("IDA restructures the while loop as while(1)+break on mips")

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from WhileStmt ws
    select ws, ws.getCondition(), ws.getStmt()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert matrix[0][0] == "WhileStmt", "Expected WhileStmt"
    assert (
        matrix[0][1]
        == "(FunctionCall to Function getValue) <= (PositiveIntNumberLiteral: 4 (0x4))"
    ), "Expected as condition of WhileStmt"
    assert matrix[0][2] == "BlockStmt", "Expected as statement of WhileStmt"


def test_TryThrowStmt(compile_extract_session, ida_version):
    """
    TryStmt with `catch (int e)` then `catch (...)` (CatchAnyBlock).

    Two concrete-type catches (e.g. int + float) degrade to `__eh34_*` intrinsics instead
    of `cit_try`, hence this shape. x86_64 MSVC-ABI only: Hex-Rays builds cit_try/cit_throw
    solely from MSVC EH tables, never from Itanium `__cxa_throw`.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)
    test_dir = test_file.parent

    db_dir = test_dir / "databases" / f"test_TryThrowStmt_IDA-{ida_version}_arch-x86_64"
    db_dir.mkdir(parents=True, exist_ok=True)
    compile_extract_session(test_dir, "stmt_try_throw", arch="x86_64", db_dir=db_dir)

    query = """
    import binary
    from TryStmt t, CatchBlock cb0, CatchBlock cb1
    where t.getEnclosingFunction().getName() = "main"
        and cb0 = t.getCatchClause(0) and cb1 = t.getCatchClause(1)
    select t.getNumberOfCatchClauses(), t.getTriedBodyLength(), count(t.getATriedStmt()),
        count(cb0.getABodyStmt()), cb0.getCaughtType().toString(),
        count(LocalVariableAccess lva | lva = cb0.getParameter()),
        count(CatchAnyBlock cab | cab = cb0),
        count(cb1.getABodyStmt()), count(CatchAnyBlock cab | cab = cb1)
    """

    matrix = run_codeql_query(src_dir, db_dir, query)
    pprint(matrix)
    assert matrix[0] == [
        "2",
        "2",
        "2",
        "3",
        "int",
        "1",
        "0",
        "3",
        "1",
    ], (
        "Expected 2 catch clauses; clause 0 catches `int` with 3 body "
        "statements (not a CatchAnyBlock); clause 1 is a 3-statement "
        "CatchAnyBlock"
    )


def test_ThrowStmt(compile_extract_session, ida_version):
    """`risky` throws twice (int, then float); x86_64/MSVC-only, see test_TryThrowStmt."""
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)
    test_dir = test_file.parent

    db_dir = test_dir / "databases" / f"test_ThrowStmt_IDA-{ida_version}_arch-x86_64"
    db_dir.mkdir(parents=True, exist_ok=True)
    compile_extract_session(test_dir, "stmt_try_throw", arch="x86_64", db_dir=db_dir)

    query = """
    import binary
    select count(ThrowStmt t | t.getEnclosingFunction().getName() = "?risky@@YAHH@Z")
    """

    matrix = run_codeql_query(src_dir, db_dir, query)
    pprint(matrix)
    assert matrix[0][0] == "2", "Expected exactly 2 ThrowStmt in `risky`"
