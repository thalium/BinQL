/**
 * Provides representations of C/C++ binary operations.
 *
 * This file defines the `BinaryOperation` class as the root for all binary expressions,
 * including logical, bitwise, comparison, and arithmetic operations.
 *
 * Binary operations model expressions with two operands, such as:
 *  - Logical operations: `LogicalAndExpr`, `LogicalOrExpr`
 *  - Bitwise operations: `BitwiseAndExpr`, `BitwiseOrExpr`, `BitwiseXorExpr`, `LShiftExpr`, `RShiftExpr`
 *  - Comparison operations: `EQExpr`, `NEExpr`, `GTExpr`, `LTExpr`, `GEExpr`, `LEExpr`
 *  - Arithmetic operations: `AddExpr`, `SubExpr`, `MulExpr`, `DivExpr`, `RemExpr`
 *
 * Signed and unsigned variants are represented where applicable, e.g., `SignedIntDivExpr` and `UnsignedIntDivExpr`.
 */

import binary

/**
 * A C/C++ binary operation.
 */
class BinaryOperation extends Operation, @ens_binaryoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "BinaryOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "BinaryOperation " + this.getLocation() }
}

/**
 * A C/C++ binary logical operation.
 */
class BinaryLogicalOperation extends BinaryOperation, @ens_binarylogicalloperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "BinaryLogicalOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "BinaryLogicalOperation " + this.getLocation() }
}

/**
 * A C/C++ logical OR expression.
 *
 * `if (a || b) { }`
 */
final class LogicalOrExpr extends BinaryLogicalOperation, @logicalorexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") || (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "LogicalOrExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ logical AND expression.
 *
 * `if (a && b) { }`
 */
final class LogicalAndExpr extends BinaryLogicalOperation, @logicalandexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") && (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "LogicalAndExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ binary bitwise operation.
 */
class BinaryBitwiseOperation extends BinaryOperation, @ens_binarybitwiseoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "BinaryBitwiseOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "BinaryBitwiseOperation" + this.getLocation() }
}

/**
 * A C/C++ bitwise OR expression.
 *
 * `c = a | b;`
 */
final class BitwiseOrExpr extends BinaryBitwiseOperation, @bitwiseorexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") | (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "BitwiseOrExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ bitwise XOR expression.
 *
 * `c = a ^ b;`
 */
final class BitwiseXorExpr extends BinaryBitwiseOperation, @bitwisexorexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") ^ (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "BitwiseXorExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ bitwise AND expression.
 *
 * `c = a & b;`
 */
final class BitwiseAndExpr extends BinaryBitwiseOperation, @bitwiseandexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") & (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "BitwiseAndExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ sign-agnostic bitwise right shift expression.
 *
 * `c = a >> b;`
 */
class RShiftExpr extends BinaryBitwiseOperation, @ens_rshiftexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") >> (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "RShiftExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ signed bitwise right shift expression.
 *
 * `c = a >> (signed) b;`
 */
final class SignedRShiftExpr extends RShiftExpr, @signedrshiftexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") >> (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "SignedRShiftExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ unsigned bitwise right shift expression.
 *
 * `c = a >> (unsigned) b;`
 */
final class UnsignedRShiftExpr extends RShiftExpr, @unsignedrshiftexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") >> (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "UnsignedRShiftExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ sign-agnostic bitwise left shift expression.
 *
 * `c = a << b;`
 */
final class LShiftExpr extends BinaryBitwiseOperation, @lshiftexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") << (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "LShiftExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ comparison operation, that is, either an equality operation or a relational operation.
 *
 * This is a QL base class for all comparisons.
 */
class ComparisonOperation extends BinaryOperation, @ens_comparisonoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "ComparisonOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "ComparisonOperation " + this.getLocation() }
}

/**
 * A C/C++ equality operation, that is, either "==" or "!=".
 */
class EqualityOperation extends ComparisonOperation, @ens_equalityoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "EqualityOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "EqualityOperation " + this.getLocation() }
}

/**
 * A C/C++ equal expression.
 * ```
 * bool c = (a == b);
 * ```
 */
final class EQExpr extends EqualityOperation, @eqexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") == (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "EQExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ not equal expression.
 * ```
 * bool c = (a != b);
 * ```
 */
final class NEExpr extends EqualityOperation, @neexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") != (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "NEExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ relational operation, that is, one of `<=`, `<`, `>`, or `>=`.
 */
class RelationOperation extends ComparisonOperation, @ens_relationoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "RelationOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "RelationOperation " + this.getLocation() }
}

/**
 * A C/C++ sign-agnostic greater than or equal expression.
 * ```
 * bool c = (a >= b);
 * ```
 */
class GEExpr extends RelationOperation, @ens_geexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") >= (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "GEExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ signed greater than or equal expression.
 * ```
 * bool c = (a >= (signed) b);
 * ```
 */
final class SignedGEExpr extends GEExpr, @signedgeexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") >= (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "SignedGEExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ unsigned greater than or equal expression.
 * ```
 * bool c = (a >= (unsigned) b);
 * ```
 */
final class UnsignedGEExpr extends GEExpr, @unsignedgeexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") >= (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "UnsignedGEExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ sign-agnostic less than or equal expression.
 * ```
 * bool c = (a <= b);
 * ```
 */
class LEExpr extends RelationOperation, @ens_leexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") <= (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "LEExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ signed less than or equal expression.
 * ```
 * bool c = (a <= (signed) b);
 * ```
 */
final class SignedLEExpr extends LEExpr, @signedleexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") <= (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "SignedLEExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ unsigned less than or equal expression.
 * ```
 * bool c = (a <= (unsigned) b);
 * ```
 */
final class UnsignedLEExpr extends LEExpr, @unsignedleexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") <= (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "UnsignedLEExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ sign-agnostic greater than expression.
 * ```
 * bool c = (a > b);
 * ```
 */
class GTExpr extends RelationOperation, @ens_gtexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") > (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "GTExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ signed greater than expression.
 * ```
 * bool c = (a > (signed) b);
 * ```
 */
final class SignedGTExpr extends GTExpr, @signedgtexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") > (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "SignedGTExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ unsigned greater than expression.
 * ```
 * bool c = (a > (unsigned) b);
 * ```
 */
final class UnsignedGTExpr extends GTExpr, @unsignedgtexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") > (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "UnsignedGTExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ sign-agnostic less than expression.
 * ```
 * bool c = (a < b);
 * ```
 */
class LTExpr extends RelationOperation, @ens_ltexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") < (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "LTExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ signed less than expression.
 * ```
 * bool c = (a < (signed) b);
 * ```
 */
final class SignedLTExpr extends LTExpr, @signedltexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") < (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "SignedLTExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ unsigned less than expression.
 * ```
 * bool c = (a < (unsigned) b);
 * ```
 */
final class UnsignedLTExpr extends LTExpr, @unsignedltexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") < (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "UnsignedLTExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ binary arithmetic operation.
 *
 * This is an abstract base QL class for all binary arithmetic operations.
 */
class BinaryArithmeticOperation extends BinaryOperation, @ens_binaryarithmeticoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "BinaryArithmeticOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "BinaryArithmeticOperation " + this.getLocation() }
}

/**
 * A C/C++ add expression.
 * ```
 * c = a + b;
 * ```
 */
class AddExpr extends BinaryArithmeticOperation, @ens_addexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") + (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "AddExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ integer addition expression.
 * ```
 * c = (int)a + (int)b;
 * ```
 */
final class IntAddExpr extends AddExpr, @intaddexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") + (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "IntAddExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ float addition expression
 * ```
 * c = (float)a + (float)b;
 * ```
 */
final class FloatAddExpr extends AddExpr, @floataddexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") + (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "FloatAddExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ subtract expression.
 * ```
 * c = a - b;
 * ```
 */
class SubExpr extends BinaryArithmeticOperation, @ens_subexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") - (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "SubExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ integer subtract expression.
 * ```
 * c = (int)a - (int)b;
 * ```
 */
final class IntSubExpr extends SubExpr, @intsubexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") - (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "IntSubExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ float subtract expression.
 * ```
 * c = (float)a - (float)b;
 * ```
 */
final class FloatSubExpr extends SubExpr, @floatsubexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") - (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "FloatSubExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ multiply expression.
 * ```
 * c = a * b;
 * ```
 */
class MulExpr extends BinaryArithmeticOperation, @ens_mulexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") * (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "MulExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ integer multiply expression.
 * ```
 * c = (int)a * (int)b;
 * ```
 */
final class IntMulExpr extends MulExpr, @intmulexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") * (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "IntMulExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ float multiply expression.
 * ```
 * c = (float)a * (float)b;
 * ```
 */
final class FloatMulExpr extends MulExpr, @floatmulexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") * (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "FloatMulExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ divide expression.
 * ```
 * c = a / b;
 * ```
 */
class DivExpr extends BinaryArithmeticOperation, @ens_divexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") / (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "DivExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ sign-agnostic integer divide expression.
 * ```
 * c = (int)a / (int)b;
 * ```
 */
class IntDivExpr extends DivExpr, @ens_intdivexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") / (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "IntDivExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ signed integer divide expression.
 * ```
 * c = (int)a / (signed) (int)b;
 * ```
 */
final class SignedIntDivExpr extends IntDivExpr, @signedintdivexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") / (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "SignedIntDivExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ unsigned integer divide expression.
 * ```
 * c = (int)a / (unsigned) (int)b;
 * ```
 */
final class UnsignedIntDivExpr extends IntDivExpr, @unsignedintdivexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") / (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "UnsignedIntDivExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ float divide expression.
 * ```
 * c = (float)a / (float)b;
 * ```
 */
final class FloatDivExpr extends DivExpr, @floatdivexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") / (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "FloatDivExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ sign-agnostic remainder expression.
 * ```
 * c = a % b;
 * ```
 */
class RemExpr extends BinaryArithmeticOperation, @ens_remexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") % (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "RemExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ signed remainder expression.
 * ```
 * c = a % (signed) b;
 * ```
 */
final class SignedRemExpr extends RemExpr, @signedremexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") % (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "SignedRemExpr: " + this.toString() + " " + this.getLocation() }
}

/**
 * A C/C++ unsigned remainder expression.
 * ```
 * c = a % (unsigned) b;
 * ```
 */
final class UnsignedRemExpr extends RemExpr, @unsignedremexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "(" + this.getLeftChild() + ") % (" + this.getRightChild() + ")" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "UnsignedRemExpr: " + this.toString() + " " + this.getLocation() }
}
