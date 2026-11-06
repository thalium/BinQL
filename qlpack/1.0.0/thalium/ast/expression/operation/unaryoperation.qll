/**
 * Provides representations of C/C++ unary expressions and operations.
 *
 * This file defines the QL class hierarchy for unary operations, including:
 * - Unary logical operations (e.g., `!a`)
 * - Unary bitwise operations (e.g., `~a`)
 * - Unary arithmetic operations (`++` and `--`, both prefix and postfix)
 * - Pointer dereference (`*ptr`) and address-of (`&var`) expressions
 *
 * Each class provides methods to obtain a textual and debug representation of the expression.
 */

import binary

/**
 * A C/C++ unary operation.
 */
class UnaryOperation extends Operation, @ens_unaryoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "UnaryOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "UnaryOperation " + this.getLocation() }
}

/**
 * A C/C++ unary logical operation.
 */
class UnaryLogicalOperation extends UnaryOperation, @ens_unarylogicaloperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "UnaryLogicalOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "UnaryLogicalOperation " + this.getLocation() }
}

/**
 * A C/C++ logical not expression.
 *
 * `c = !a;`.
 */
final class NotExpr extends UnaryLogicalOperation, @logicnotexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "NotExpr" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "NotExpr " + this.getLocation() }
}

/**
 * A C/C++ unary bitwise operation.
 *
 * Example:
 *
 * ComplementExpr `~ Expr`
 */
class UnaryBitwiseOperation extends UnaryOperation, @ens_unarybitwiseoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "UnaryOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "UnaryOperation " + this.getLocation() }
}

/**
 * A C/C++ complement expression.
 *
 * `unsigned c = ~a;`
 */
class ComplementExpr extends UnaryBitwiseOperation, @bitwisenotexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "ComplementExpr" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "ComplementExpr " + this.getLocation() }
}

/**
 * An instance of the built-in unary `operator *` applied to a type.
 *
 * ```
 * int var = *varptr;
 * ```
 */
final class PointerDereferenceExpr extends UnaryOperation, @pointerdereferenceexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "PointerDereferenceExpr " + this.getChild(0) }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "PointerDereferenceExpr " + this.getLocation() }
}

/**
 * A C/C++ address-of expression.
 *
 * Here `&var` is an AddressOfExpr.
 * `int *ptr = &var;`
 */
class AddressOfExpr extends UnaryOperation, @addressofexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "AddressOfExpr" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "AddressOfExpr " + this.getLocation() }
}

/**
 * A C/C++ unary arithmetic operation.
 */
class UnaryArithmeticOperation extends UnaryOperation, @ens_unaryarithmeticoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "UnaryArithmeticOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "UnaryArithmeticOperation " + this.getLocation() }
}

/**
 * A C/C++ `++` or `--` expression (either prefix or postfix).
 *
 * This is the base QL class for increment and decrement operations.
 */
class CrementOperation extends UnaryArithmeticOperation, @ens_crementoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "CrementOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "CrementOperation " + this.getLocation() }
}

/**
 * A C/C++ `--` expression (either prefix or postfix).
 */
class DecrementOperation extends CrementOperation, @ens_decrementoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "DecrementOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "DecrementOperation " + this.getLocation() }
}

/**
 * A C/C++ `++` expression (either prefix or postfix).
 */
class IncrementOperation extends CrementOperation, @ens_incrementoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "IncrementOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "IncrementOperation " + this.getLocation() }
}

/**
 * A C/C++ `++` or `--` prefix expression.
 */
class PrefixCrementOperation extends CrementOperation, @ens_prefixcrementoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "PrefixOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "PrefixOperation " + this.getLocation() }
}

/**
 * A C/C++ `++` or `--` postfix expression.
 */
class PostfixCrementOperation extends CrementOperation, @ens_postfixcrementoperation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "PostfixOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "PostfixOperation " + this.getLocation() }
}

/**
 * A C/C++ `--` prefix expression.
 */
final class PrefixDecrementExpr extends PrefixCrementOperation, DecrementOperation, @prefixdecrexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "PrefixDecrementOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "PrefixDecrementOperation " + this.getLocation() }
}

/**
 * A C/C++ postfix decrement expression, as in `x--`.
 *
 * `b = a--;`
 */
final class PostfixDecrExpr extends PostfixCrementOperation, DecrementOperation, @postfixdecrexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "PostfixDecrementOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "PostfixDecrementOperation " + this.getLocation() }
}

/**
 * A C/C++ prefix increment expression, as in `++x`.
 *
 * `b = ++a;`
 */
final class PrefixIncrExpr extends PrefixCrementOperation, IncrementOperation, @prefixincrexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "PrefixIncrementOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "PrefixIncrementOperation " + this.getLocation() }
}

/**
 * A C/C++ postfix increment expression, as in `x++`.
 *
 * `b = a++;`
 */
final class PostfixIncrExpr extends PostfixCrementOperation, IncrementOperation, @postfixincrexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "PostfixIncrementOperation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "PostfixIncrementOperation " + this.getLocation() }
}
