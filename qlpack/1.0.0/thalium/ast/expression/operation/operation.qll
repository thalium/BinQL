/**
 * Provides representations of C/C++ operations.
 *
 * This file defines the `Operation` class as the root for all C/C++ expressions
 * that perform some computation or produce a value, including:
 *  - `ConditionalExpr`: ternary conditional expressions (`a = (b > c ? d : e);`)
 *
 * These classes model operational expressions in C/C++ code and can serve
 * as a base for more specific operation types like unary, binary, or memory operations.
 */

import binary

/**
 * A C/C++ operation.
 *
 * This is the QL root class for all operations.
 */
class Operation extends Expression, @ens_operation {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "Operation" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "Operation " + this.getLocation() }
}

/**
 * A C/C++ conditional ternary expression.
 *
 * `a = (b > c ? d : e);`
 */
final class ConditionalExpr extends Operation, @conditionalexprs {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "ConditionalExpr" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "ConditionalExpr " + this.getLocation() }
}
