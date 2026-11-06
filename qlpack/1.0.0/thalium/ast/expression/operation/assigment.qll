/**
 * Provides representations of C/C++ assignment operations, from simple
 * assignment (`a = b`) to compound arithmetic, bitwise, shift, and
 * remainder assignments (e.g., `a += b`, `a &= b`, `a >>= b`).
 */

import binary

/**
 * Represents any assignment.
 */
class Assignment extends Operation, @ens_assignment {

  /**
 * Returns a string representation of the statement, including its location.
 */
  override string toString() { result = "Assignment: " + this.getUnderlyingType() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "Assignment: " + this.getUnderlyingType() + " at " + this.getLocation() }

  /**
   * Returns the underlying QL class name representing the type of this assignment.
   */
  string getUnderlyingType() {
    result = this.getAPrimaryQlClass()
  }
}

/**
 * Represents an assignment statement in the source code.
 *
 * Assignment statements include simple assignments (`=`) and compound assignments (e.g., `+=`, `*=`).
 * This class serves as a base for more specific assignment expressions.
 */
class AssignOperation extends Assignment, @ens_assignoperation {
  /**
   * Returns a string representation of the assignment, including its type and location.
   */
  override string toString() { result = "AssignOperation: " + this.getUnderlyingType() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "AssignOperation: " + this.getUnderlyingType() + " at " + this.getLocation() }

  /**
   * Returns the underlying QL class name representing the type of this assignment.
   */
  override string getUnderlyingType() {
    result = this.getAPrimaryQlClass()
  }
}

/**
 * Represents AssignArithmeticOperation expression.
 */
class AssignArithmeticOperation extends AssignOperation, @ens_assignarithmeticoperation {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignArithmeticOperation" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignArithmeticOperation: " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents an assignment with an equality operator (e.g., `a = b`).
 */
final class AssignExpr extends AssignArithmeticOperation, @assignexprs {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignExpr" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignExpr: " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents an addition compound assignment expression (e.g., `a += b`).
 */
final class AssignAddExpr extends AssignArithmeticOperation, @assignaddexprs {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignAddExpr" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignAddExpr of " + this.getChild(0) + " and " + this.getChild(1) }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "AssignAddExpr of " + this.getChild(0) + " and " + this.getChild(1) + " at " + this.getLocation() }
}

/**
 * Represents a multiplication compound assignment expression (e.g., `a *= b`).
 */
final class AssignMulExpr extends AssignArithmeticOperation, @assignmulexprs {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignMulExpr" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignMulExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents a simple assignment expression (e.g., `a = b`).
 */
class AssignBitwiseOperation extends AssignOperation, @ens_assignbitwiseoperation {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignBitwiseOperation" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignBitwiseOperation: " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents a multiplication compound assignment expression (e.g., `a |= b`).
 */
final class AssignOrExpr extends AssignBitwiseOperation, @assignorexprs {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignOrExpr" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignOrExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents a bitwise XOR compound assignment expression (e.g., `a ^= b`).
 */
final class AssignXorExpr extends AssignBitwiseOperation, @assignxorexprs {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignXorExpr" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignXorExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents a bitwise AND compound assignment expression (e.g., `a &= b`).
 */
final class AssignAndExpr extends AssignBitwiseOperation, @assignandexprs {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignAndExpr" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignAndExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents right shift compound assignment expressions (e.g., `a >>= b (un)signed`).
 */
abstract class AssignRShiftExpr extends AssignBitwiseOperation {
  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignRShiftExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents a signed right shift compound assignment (e.g., `a >>= b signed`).
 */
final class AssignSignedRShiftExpr extends AssignRShiftExpr, @assignsignedrshiftexprs {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignSignedRShiftExpr" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignSignedRShiftExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents an unsigned right shift compound assignment (e.g., `a >>= b unsigned`).
 */
final class AssignUnsignedRShiftExpr extends AssignRShiftExpr, @assignunsignedrshiftexprs {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignUnsignedRShiftExpr" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignUnsignedRShiftExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents a left shift compound assignment expression (e.g., `a <<= b`).
 */
final class AssignLShiftExpr extends AssignBitwiseOperation, @assignlshiftexprss {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignLShiftExpr" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignLShiftExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents a division compound assignment expressions (e.g., `a /= b (un)signed`).
 */
abstract class AssignDivExpr extends AssignBitwiseOperation {
  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignDivExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents a signed division compound assignment (e.g., `a /= b` with signed operands).
 */
final class AssignSignedDivExpr extends AssignDivExpr, @assignsigneddivexprs {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignSignedDivExpr" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignSignedDivExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents an unsigned division compound assignment (e.g., `a /= b` with unsigned operands).
 */
final class AssignUnsignedDivExpr extends AssignDivExpr, @assignunsigneddivexprs {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignUnsignedDivExpr" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignUnsignedDivExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents a remainder compound assignment expressions (e.g., `a %= b (un)signed`).
 */
abstract class AssignRemExpr extends AssignBitwiseOperation {
  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignRemExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents a signed remainder compound assignment (e.g., `a %= b` with signed operands).
 */
final class AssignSignedRemExpr extends AssignRemExpr, @assignsignedremexprs {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignSignedRemExpr" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignSignedRemExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}

/**
 * Represents an unsigned remainder compound assignment (e.g., `a %= b` with unsigned operands).
 */
final class AssignUnsignedRemExpr extends AssignRemExpr, @assignunsignedremexprs {
  /**
   * Gets the primary QL class name for this expression.
   */
  override string getAPrimaryQlClass() { result = "AssignUnsignedRemExpr" }

  /**
   * Returns a string showing the left-hand side and right-hand side expressions.
   */
  override string toString() { result = "AssignUnsignedRemExpr of " + this.getChild(0) + " and " + this.getChild(1) }
}
