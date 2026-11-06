/**
 * Provides representations of C/C++ expressions.
 *
 * This file defines the QL classes for modeling various kinds of expressions in C/C++:
 * - `Expression`: The root class for all expressions.
 * - `EmptyExpr`: Represents an empty statement expression (`;`).
 * - `CommaExpr`: Represents a comma expression (`expr1, expr2, ...`).
 * - `Cast`: The base class for cast expressions.
 * - `CStyleCast`: Represents a C-style cast (or C-style cast in C++).
 *
 * Each class provides methods to obtain a textual representation and access
 * associated metadata, such as the target type for casts.
 */


import binary

/**
 * A C/C++ expression.
 *
 * This is the root QL class for all expressions.
 */
class Expression extends Node, @ens_expr {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "Expression" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "Expression " + this.getLocation() }
}

/**
 * A C/C++ array access expression.
 *
 * ```
 * a[i]
 * ```
 */
final class ArrayExpr extends Expression, @arrayexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "ArrayExpr: " + this.getChild(0) + "[" + this.getChild(1) + "]"}
}

/**
 * A C/C++ empty statement expression.
 * *
 * ```
 * void f() {
 *     ;
 * }
 * ```
 */
final class EmptyExpr extends Expression, @emptyexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "EmptyExpr"}

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "EmptyExpr " + this.getLocation() }
}

/**
 * A C/C++ comma expression.
 *
 * ```
 * int c = compute1(), compute2(), resulting_value;
 * ```
 */
final class CommaExpr extends Expression, @commaexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "CommaExpr" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "CommaExpr " + this.getLocation() }
}

/**
 * A C/C++ cast expression.
 *
 * To get the type which the expression is being cast to, use `Cast::getType()`.
 *
 * This is a root QL class representing the different casts.
 */
class Cast extends Expression, @ens_cast {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "Cast" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "Cast " + this.getLocation() }
}

/**
 * A cast expression in C, or a C-style cast expression in C++.
 * ```
 * float f = 3.0f;
 * int i = (int)f;
 * ```
 */
final class CStyleCast extends Cast, @castexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "CStyleCast to " + this.getTarget() + " of " + this.getChild(0) }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "CStyleCast to " + this.getTarget() + " at " + this.getLocation() }

  /**
   * Gets the target type of this cast operation.
   */
  string getTarget() { castexprs(this, result) }
}

/**
 * A C/C++ `sizeof` operator.
 *
 * This is a root QL class representing the different `sizeof` expressions.
 */
abstract class SizeofOperator extends Expression {}

/**
 * A `sizeof` expression applied to an expression operand.
 *
 * ```
 * sizeof(x)
 * ```
 */
final class SizeofExprOperator extends SizeofOperator, @sizeofexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "SizeofExprOperator to " + this.getChild(0) }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = this.toString() + " at " + this.getLocation() }
}
