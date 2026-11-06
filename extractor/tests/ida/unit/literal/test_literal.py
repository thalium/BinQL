from pathlib import Path
from pprint import pprint

import pytest
from conftest import parametrize_binary
from utils.helpers import get_src_dir, run_codeql_query


@parametrize_binary("compiled_extracted_binary", ["literal_int_pos"])
def test_PositiveIntNumberLiteral(compiled_extracted_binary, arch, ida_version):
    """
    Test that positive integer literals in the `main` function are correctly identified.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from PositiveIntNumberLiteral n
    where n.getEnclosingFunction().getName().matches("%main%")
    select n.getValue()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert ["123"] in matrix


@parametrize_binary("compiled_extracted_binary", ["literal_int_neg"])
def test_NegativeIntNumberLiteral(compiled_extracted_binary, arch, ida_version):
    """
    Test that negative integer literals in the `main` function are correctly identified.
    """
    if arch == "x86_32":
        pytest.xfail(
            "`-123456` is not regognized out of the box by IDA as a negative integer on x86_32"
        )

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from NegativeIntNumberLiteral n
    where n.getEnclosingFunction().getName().matches("%main%")
    select n.getValue()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)

    assert matrix[0] == ["-123"]


@parametrize_binary("compiled_extracted_binary", ["literal_float"])
def test_FloatNumberLiteral(compiled_extracted_binary, arch, ida_version):
    """
    Test that floating-point literals in the `main` function are correctly identified.
    """
    if arch in ("x86_32", "ppc32", "ppc64", "mips32", "mips64"):
        pytest.xfail(
            "`-123.456` not recognised as a float by IDA on x86_32 / soft-float ppc/mips"
        )

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from FloatNumberLiteral n
    where n.getEnclosingFunction().getName().matches("%main%")
    select n.getValue()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert "-123.456" in matrix[0][0]


@parametrize_binary("compiled_extracted_binary", ["literal_float_nan"])
def test_FloatNumberLiteral_NonFinite(compiled_extracted_binary, arch, ida_version):
    """
    NaN/Infinity survive as their exact spelling (`floatnumberliterals.value` is a
    string column; the TRAP reader has no float token for `-Infinity`).

    `-Infinity` is not asserted: Hex-Rays emits `-INFINITY` as `fneg(INFINITY)`, not a
    negative `cot_fnum`, so it is not covered by this test.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from FloatNumberLiteral n
    where n.getEnclosingFunction().getName().matches("%main%")
    select n.getValue()
    """

    if arch in ("ppc32", "ppc64", "mips32", "mips64"):
        pytest.xfail(
            "NaN/Infinity float literals are not emitted by IDA on the soft-float ppc/mips ABIs"
        )

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    values = {row[0] for row in matrix}
    assert values >= {"NaN", "Infinity"}


@parametrize_binary("compiled_extracted_binary", ["literal_string"])
def test_StringLiteral(compiled_extracted_binary, arch, ida_version):
    """
    Test that string literals in the `main` function are correctly identified.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from StringLiteral str
    where str.getEnclosingFunction().getName().matches("%main%")
    select str.getString()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    # on mips `main` also refs the `.__cxa_finalize` symbol string, which sorts first
    assert ["Hello"] in matrix


@parametrize_binary("compiled_extracted_binary", ["literal_uint_full"])
def test_PositiveIntNumberLiteral_UnsignedFull(
    compiled_extracted_binary, arch, ida_version
):
    """
    0xFFFFFFFF is outside int32: `getIntValue()` has no row, the total accessors do.
    See https://github.com/github/codeql/issues/4691.
    """
    if arch in ("x86_32", "arm32", "ppc32", "mips32"):
        pytest.xfail(
            "32-bit targets decompile a >INT32_MAX literal as a sign-reinterpreted -1"
        )

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from IntNumberLiteral n
    where n.getEnclosingFunction().getName().matches("%main%") and n.getHexValue() = "0xffffffff"
    select n.getValueString(), n.getHexValue(), count(n.getIntValue())
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert ["4294967295", "0xffffffff", "0"] in matrix


@parametrize_binary("compiled_extracted_binary", ["literal_uint_mask"])
def test_PositiveIntNumberLiteral_Mask(compiled_extracted_binary, arch, ida_version):
    """`x & 0xFFFFFFFE` mask idiom (zlib deflateInit2_): the wide operand is reachable and hex-renderable."""
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from BitwiseAndExpr band, IntNumberLiteral mask
    where
      band.getEnclosingFunction().getName().matches("%round_down_even%") and
      band.getAChild+() = mask and
      mask.getHexValue() = "0xfffffffe"
    select mask.getValueString(), mask.getHexValue()
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert ["4294967294", "0xfffffffe"] in matrix


@parametrize_binary("compiled_extracted_binary", ["literal_int_pos_large"])
def test_PositiveIntNumberLiteral_Large(compiled_extracted_binary, arch, ida_version):
    """Unmasked literal > INT32_MAX: total accessors resolve, `getIntValue()` does not."""
    if arch in ("x86_32", "arm32", "ppc32", "mips32"):
        pytest.xfail(
            "32-bit targets decompile a >INT32_MAX literal as a sign-reinterpreted -1"
        )

    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from IntNumberLiteral n
    where n.getEnclosingFunction().getName().matches("%main%") and n.getValueF() = 4294967294.0
    select n.getValueString(), n.getHexValue(), count(n.getIntValue())
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    assert ["4294967294", "0xfffffffe", "0"] in matrix


@parametrize_binary("compiled_extracted_binary", ["literal_overlay_mask"])
def test_overlay_mask_survives(compiled_extracted_binary, arch, ida_version):
    """
    Regression for CVE-2018-25032's `deflateInit2_` shape (two slices of one base,
    one via `& 0xFFFFFFFE`): the masked assignment used to vanish from the DB.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    query = """
    import binary
    from Function f
    where f.getName().matches("%slice%")
    select
      count(AssignExpr a | a.getEnclosingFunction() = f),
      count(BitwiseAndExpr b | b.getEnclosingFunction() = f),
      count(IntNumberLiteral n |
        n.getEnclosingFunction() = f and n.getHexValue() = "0xfffffffe")
    """

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, query)
    pprint(matrix)
    n_asg, n_band, n_mask = (int(x) for x in matrix[0])
    # arm32 + the RISC back-ends inline both slice locals into one assignment
    inlines_slices = ("arm32", "ppc32", "ppc64", "mips32", "mips64", "riscv64")
    assert n_asg >= (1 if arch in inlines_slices else 2)
    assert n_band >= 1
    assert n_mask >= 1


_ESCAPE_QUERY = """
import binary
from StringLiteral s
where s.getEnclosingFunction().getName().matches("%main%")
select s.getString()
"""

# Expected getString() per literal in literal_string_escape.c. These two avoid every
# downstream quirk (no comma, no CR, all printable), so they prove raw-byte/quote escaping.
_ESCAPE_CLEAN = {
    "quotes": 'q=" and \\" and end\\',
    "fmt": "100%% done: %s %d %p",
}
# Full set, for the documented-gap round-trip below.
_ESCAPE_ALL = {
    **_ESCAPE_CLEAN,
    "apostr": "it's a 'trap', don't you 'think'?",
    "ws": "tab[\t]nl[\n]cr[\n]end",  # \r normalised to \n by the TRAP reader
    "ctrl": "ctrl[\x01\x02\x1f]end",
    "trapchars": "struct( a , b ) ; x = y * z",
    "utf8": "café ✓ \U0001f4a9",
}


@parametrize_binary("compiled_extracted_binary", ["literal_string_escape"])
def test_StringLiteral_Escaping(compiled_extracted_binary, arch, ida_version):
    """
    ``"`` and ``\\`` round-trip without breaking the TRAP line.

    A bad escape makes the TRAP reader reject the line, dropping the whole enclosing
    function. Relies on ``cot_obj`` reading raw strlit bytes (not IDA's display
    text) and ``trap_escape`` doubling ``"`` rather than JSON-escaping it.
    """
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, _ESCAPE_QUERY)
    pprint(matrix)
    values = {row[0] for row in matrix}

    assert values, "main has no string literals -- a payload broke its TRAP line"
    missing = set(_ESCAPE_CLEAN.values()) - values
    assert not missing, f"string literal corrupted or dropped: {missing!r}"


@pytest.mark.xfail(
    reason=(
        "full round-trip is blocked downstream of the extractor: CodeQL's TRAP "
        "reader rewrites \\r -> \\n, the test harness' load_csv_matrix mangles "
        "values containing a comma, and IDA never types the control-byte / "
        "high-UTF-8 .rodata blobs as strings (get_strlit_contents truncates)"
    ),
    strict=False,
)
@parametrize_binary("compiled_extracted_binary", ["literal_string_escape"])
def test_StringLiteral_Escaping_RoundTrip(compiled_extracted_binary, arch, ida_version):
    """XPASS means a downstream quirk was fixed -- fold into the hard test above."""
    test_file = Path(__file__)
    src_dir = get_src_dir(test_file)

    matrix = run_codeql_query(src_dir, compiled_extracted_binary, _ESCAPE_QUERY)
    pprint(matrix)
    values = {row[0] for row in matrix}

    missing = set(_ESCAPE_ALL.values()) - values
    assert not missing, f"string literals corrupted or dropped: {missing!r}"
