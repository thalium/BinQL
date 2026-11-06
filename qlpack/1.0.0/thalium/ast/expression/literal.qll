/**
 * Provides representations of C/C++ literals.
 *
 */

import binary

/**
 * A C/C++ literal.
 *
 * The is the QL root class for all literals.
 */
class Literal extends Expression, @ens_literal {
  /**
   * Gets a textual representation of this literal.
   */
  override string toString() { result = "Literal" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "Literal " + this.getLocation() }
}

/**
 * A C/C++ number literal.
 */
class NumberLiteral extends Literal, @ens_numberliteral {
  /**
   * Gets the integer value as a 32-bit `int`. No result outside
   * `[INT32_MIN, INT32_MAX]`; use `IntNumberLiteral.getBigIntValue()` (total).
   */
  int getIntValue() { result = this.(IntNumberLiteral).getInt32Value() }

  /**
   * Gets the floating-point value of this literal (if it is a float). No
   * result for a non-finite literal (`NaN` / `±Infinity`) - read
   * `FloatNumberLiteral.getValue(): string` for those.
   */
  float getFloatValue() { result = this.(FloatNumberLiteral).getValueF() }

  /**
   * Gets the value of this literal as a `float` - total for every number
   * literal except a non-finite float (`NaN` / `±Infinity`). Lossless for
   * every `uint32`/`int32` and for signed-reinterpreted 64-bit values up to
   * 2^53.
   */
  float getNumericValue() {
    result = this.(IntNumberLiteral).getValueF()
    or
    result = this.(FloatNumberLiteral).getValueF()
  }

  /**
   * Gets a textual representation of this literal. Total - unlike a path
   * through `getIntValue()` it does not drop out for out-of-int32 values.
   */
  override string toString() {
    this instanceof IntNumberLiteral and result = this.(IntNumberLiteral).getValueString()
    or
    this instanceof FloatNumberLiteral and result = this.(FloatNumberLiteral).getValue()
  }
}

/**
 * A C/C++ integer number literal.
 */
class IntNumberLiteral extends NumberLiteral, @ens_intnumberliteral {
  /**
   * Gets a textual representation of this literal.
   */
  override string toString() {
    result = "IntNumberLiteral: " + this.getValueString() + " (" + this.getHexValue() + ")"
  }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() {
    result =
      "IntNumberLiteral: " + this.getValueString() + " (" + this.getHexValue() + ") at " +
        this.getLocation().toString()
  }

  /**
   * Gets the exact value of this literal as a decimal number string - total, exact,
   * matching upstream CodeQL C++'s `Expr.getValue(): string`. See
   * https://github.com/github/codeql/issues/4691.
   */
  string getValue() {
    posintnumberliterals(this, result)
    or
    negintnumberliterals(this, result)
  }

  /**
   * Gets the exact value as an arbitrary-precision `QlBuiltins::BigInt` -
   * total, lossless. Prefer this for numeric comparison/bitwise work over
   * `getValue().toInt()` (see https://github.com/github/codeql/issues/4691).
   * Use for comparisons only -- a `BigInt` can't sit in a `select`; use
   * `getValue()`/`getInt32Value()` there.
   */
  QlBuiltins::BigInt getBigIntValue() { result = this.getValue().toBigInt() }

  /**
   * Gets the exact value of this literal as a `float` - total. Lossless for
   * every `uint32`/`int32` and for values up to 2^53; beyond that, prefer
   * `getBigIntValue()` for exactness.
   */
  float getValueF() { result = this.getValue().toFloat() }

  /**
   * Gets the exact value of this literal as a decimal number string - total. Alias
   * for `getValue()`, kept for callers that read this class as `float`-typed
   * (`getValueF()`/`getNumericValue()`) and want the paired total string form
   * without the name implying a bounded, `int`-typed result.
   */
  string getValueString() { result = this.getValue() }

  /**
   * Gets the value of this literal as an unsigned hex string, e.g.
   * `"0xfffffffe"` - total, and exact even past 2^53 (see `toHexBigInt()`).
   * Negative values are rendered in two's-complement 64-bit form.
   */
  string getHexValue() {
    exists(QlBuiltins::BigInt v, QlBuiltins::BigInt u |
      v = this.getBigIntValue() and
      (
        v >= 0.toBigInt() and u = v
        or
        v < 0.toBigInt() and u = v + "18446744073709551616".toBigInt() // + 2^64
      )
    |
      result = "0x" + toHexBigInt(u)
    )
  }

  /**
   * Gets the value as a 32-bit `int`. No result outside `[INT32_MIN,
   * INT32_MAX]` - by design. Use `getBigIntValue()`/`getValue()` for the
   * total accessors.
   */
  int getInt32Value() {
    exists(QlBuiltins::BigInt v |
      v = this.getBigIntValue() and
      v >= (-2147483648).toBigInt() and
      v <= 2147483647.toBigInt() and
      result = v.toInt()
    )
  }
}

/**
 * A C/C++ positive integer number literal.
 */
final class PositiveIntNumberLiteral extends IntNumberLiteral, @posintnumberliterals {
  /**
   * Gets a textual representation of this literal.
   */
  override string toString() {
    result = "PositiveIntNumberLiteral: " + this.getValueString() + " (" + this.getHexValue() + ")"
  }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() {
    result =
      "PositiveIntNumberLiteral: " + this.getValueString() + " (" + this.getHexValue() + ") at " +
        this.getLocation().toString()
  }
}

/**
 * A C/C++ negative integer number literal.
 */
final class NegativeIntNumberLiteral extends IntNumberLiteral, @negintnumberliterals {
  /**
   * Gets a textual representation of this literal.
   */
  override string toString() {
    result =
      "NegativeIntNumberLiteral: " + this.getValueString() + " (" + this.getHexValue() + ") at " +
        this.getLocation().toString()
  }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() {
    result = "NegativeIntNumberLiteral: " + this.getValueString() + " (" + this.getHexValue() + ")"
  }
}

/**
 * A C/C++ float number literal.
 */
final class FloatNumberLiteral extends NumberLiteral, @floatnumberliterals {
  /**
   * Gets a textual representation of this literal.
   */
  override string toString() { result = "FloatNumberLiteral: " + this.getValue() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() {
    result = "FloatNumberLiteral: " + this.getValue() + " at " + this.getLocation().toString()
  }

  /**
   * Gets the exact value as written: a decimal string, or `NaN` / `Infinity`
   * / `-Infinity`. Matches upstream CodeQL C++'s `Expr.getValue(): string`.
   */
  string getValue() { floatnumberliterals(this, result) }

  /**
   * Gets the value as a `float`. No result for a non-finite literal
   * (`NaN` / `±Infinity`) - use `getValue()` for those.
   */
  float getValueF() { result = this.getValue().toFloat() }
}

/**
 * A C/C++ string literal.
 */
final class StringLiteral extends Literal, @stringliterals {
  /**
   * Gets a textual representation of this literal.
   */
  override string toString() { result = "StringLiteral " + this.getString() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "StringLiteral " + this.getString() + " at " + this.getLocation() }

  /**
   * Gets the raw bytes of this string literal, decoded as UTF-8 - the actual
   * contents at the referenced address, not IDA's escaped display form. May
   * therefore contain embedded `"`, `\`, newlines, tab / control bytes and
   * non-ASCII UTF-8 verbatim (the extractor doubles `"` for TRAP and the
   * reader undoubles it; every other byte round-trips unchanged, except a
   * lone `\r` which the TRAP reader rewrites to `\n`).
   */
  string getString() { stringliterals(this, result) }
}
