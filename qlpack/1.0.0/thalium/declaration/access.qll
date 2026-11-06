/**
 * Provides representations of variable access expressions in source code.
 *
 */

import binary

/**
 * Represents an access to some declared entity (variable, field, enum constant, ...).
 */
abstract class Access extends Node, @var_acc { }

/**
 * Represents an access to a variable.
 */
class VariableAccess extends Node, @var_acc {
  /**
   * Returns a string representation of the variable access.
   */
  override string toString() { result = "VariableAccess: " + this.getTarget().getName() }

  /**
   * Gets the name of the variable accessed.
   */
  string getVariableAccessName() { result = this.getTarget().getName() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "VariableAccess: " + this.getTarget().getName() + this.getLocation() }

  /**
   * Gets the variable accessed.
   */
  Variable getTarget() {
    var_accs(this, result)
  }
}

/**
 * Represents an access to a global variable.
 */
final class GlobalVariableAccess extends VariableAccess {

  /**
   * Constructor predicate to bind this instance to accesses of global variables.
   */
  GlobalVariableAccess() {
    exists(GlobalVariable v |
      var_accs(this, v)
    )
  }

  /**
   * Returns a string representation for global variable accesses.
   */
  override string toString() { result = "GlobalVariableAccess: " + this.getName() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "GlobalVariableAccess: " + this.getName() + " at " + this.getLocation() }

  /**
   * Gets the target global variable referenced by this access.
   */
  GlobalVariable getVariable() { var_accs(this, result) }

  /**
   * Gets the name of the target global variable.
   */
  string getName() { result = this.getVariable().getName() }

  /**
   * Holds if the GobalVariableAccess has name `name`.
   */
  predicate hasName(string name) { this.getName() = name }
}

/**
 * Represents an access to a local variable.
 */
final class LocalVariableAccess extends VariableAccess {

  /**
   * Constructor predicate to bind this instance to accesses of local variables.
   */
  LocalVariableAccess() {
    exists(LocalVariable v |
      var_accs(this, v)
    )
  }

  /**
   * Returns a string representation for local variable accesses.
   */
  override string toString() { result = "LocalVariableAccess: " + this.getName() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "LocalVariableAccess: " + this.getName() + " at " + this.getLocation() }

  /**
   * Gets the target local variable referenced by this access.
   */
  LocalVariable getVariable() { var_accs(this, result) }

  /**
   * Gets the name of the target local variable.
   */
  string getName() { result = this.getVariable().getName() }

  /**
   * Holds if the LocalVariableAccess has name `name`.
   */
  predicate hasName(string name) { this.getName() = name }
}

/**
 * Represents an access to a local variable.
 */
final class ParameterVariableAccess extends VariableAccess {
  /**
   * Constructor predicate to bind this instance to accesses of parameters.
   */
  ParameterVariableAccess() {
    exists(Parameter v |
      var_accs(this, v)
    )
  }

  /**
   * Returns a string representation for local variable accesses.
   */
  override string toString() { result = "ParameterVariableAccess: " + this.getName() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "ParameterVariableAccess: " + this.getName() + " at " + this.getLocation() }

  /**
   * Gets the target local variable referenced by this access.
   */
  Parameter getVariable() { var_accs(this, result) }

  /**
   * Gets the name of the target local variable.
   */
  string getName() { result = this.getVariable().getName() }

  /**
   * Holds if the LocalVariableAccess has name `name`.
   */
  predicate hasName(string name) { this.getName() = name }
}

/**
 * A C/C++ field access expression. For example the access `y` in myFunction in the following code:
 * ```
 * void myFunction(myStruct &s) {
 *   x = s.y;
 * }
 * ```
 */
class FieldAccess extends VariableAccess {
  /**
   * Constructor predicate to bind this instance to accesses of fields.
   */
  FieldAccess() {
    exists(Field f |
      var_accs(this, f)
    )
  }

  /**
   * Gets a textual representation of this variable access.
   */
  override string toString() { result = "FieldAccess: " + this.getTarget().getName() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "FieldAccess: " + this.getTarget().getName() + " at " + this.getLocation() }
}

/**
 * A field access of the form `obj.field`.
 * The type of `obj` is either a struct/union.
 */
final class DotFieldAccess extends FieldAccess {
  /**
   * Constructor predicate to bind this instance to field accesses through a `.` qualifier.
   */
  DotFieldAccess() { this.getKind() = 59 }

  /**
   * Gets a textual representation of this variable access.
   */
  override string toString() { result = "DotFieldAccess: " + this.getTarget() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "DotFieldAccess: " + this.getTarget() + " at " + this.getLocation() }
}

/**
 * A field access whose qualifier is a pointer to a struct or union.
 * These typically take the form `obj->field`.
 */
final class PointerFieldAccess extends FieldAccess {
  /**
   * Constructor predicate to bind this instance to field accesses through a `->` qualifier.
   */
  PointerFieldAccess() { this.getKind() = 60 }

  /**
   * Gets a textual representation of this variable access.
   */
  override string toString() { result = "PointerFieldAccess: " + this.getTarget() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "PointerFieldAccess: " + this.getTarget() + " at " + this.getLocation() }
}

/**
 * Represents an access to an enum constant.
 */
final class EnumConstantAccess extends Access, @var_acc {
  /**
   * Constructor predicate to bind this instance to accesses of enum constants.
   */
  EnumConstantAccess() {
    exists(EnumConstant ec |
      var_accs(this, ec)
    )
  }

  /**
   * Returns the primary QL class name for this entity.
   */
  override string getAPrimaryQlClass() { result = "EnumConstantAccess" }

  /**
   * Gets the accessed enum constant.
   */
  EnumConstant getTarget(){ var_accs(this, result) }

  /**
   * Gets a textual representation of this `enum` constant access.
   */
  override string toString() { result = "EnumConstantAccess: " + this.getTarget().getName() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "EnumConstantAccess: " + this.getTarget() }
}
