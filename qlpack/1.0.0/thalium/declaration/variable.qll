/**
 * Provides representations of variables declared in source code.
 *
 */

import binary

/*
 * class Declaration
 * getName
 * hasName
 */

/**
 * Represents a variable.
 *
 * This is a base class for different kinds of variables such as local and global variables.
 */
class Variable extends @ens_accessables {

  /**
   * Gets an access to this variable.
   */
  VariableAccess getAnAccess() { result = this.getAnAccess() }
  /**
   * Gets the name of the variable.
   */
  string getName() { result = this.getName() }
  /**
   * Gets the type of the variable.
   */
  Type getType() { result = this.getType() }


  /**
   * Returns a string representation including the variable type and name.
   */
  string toString() { result = "Variable " + this.getType() + " " + this.getName() }

  /**
   * Holds if the Variable has name `name`.
   */
  predicate hasName(string name) { this.getName() = name }
}

/**
 * Represents a local variable declared inside a function or block.
 */
class LocalScopeVariable extends Variable, @lvar {
  /**
   * Returns a string representation including the local variable's type and name.
   */
  override string toString() { result = "LocalScopeVariable " + this.getType() + " " + this.getName() + " in " + this.getFunction() }

  /**
   * Gets the function where the local variable is located.
   */
  Function getFunction() { lvars(this, result , _, _, _) }

  /**
   * Gets the name of the local variable.
   */
  override string getName() { lvars(this, _ ,result, _, _) }

  /**
   * Checks if this local variable is a parameter of its function.
   */
   boolean isParameter() { lvars(this, _ ,_ , result, _) }

  /**
   * Holds if the LocalVariable has name `name`.
   */
  override predicate hasName(string name) { this.getName() = name }

  /**
   * Gets the type of the local variable.
   */
  override Type getType() { lvars(this, _, _, _, result) }

  /**
   *  Gets an access to this local variable.
   */
  override VariableAccess getAnAccess(){
    result.getTarget() = this
  }
}

/**
 * Represents a local variable that is not a parameter.
 */
final class LocalVariable extends LocalScopeVariable, @lvar {
  /**
   * Constructor predicate to bind this instance to local variables that are not parameters.
   */
  LocalVariable() { lvars(this, _, _, false, _) }

  /**
   * Gets an access to this local variable.
   */
  override LocalVariableAccess getAnAccess() { result.getTarget() = this }

  /**
   * Returns a string representation including the local variable's type and name.
   */
  override string toString() { result = "LocalVariable " + this.getType() + " " + this.getName() + " in " + this.getFunction() }
}

/**
 * Represents a function parameter.
 */
final class Parameter extends LocalScopeVariable, @lvar {
  /**
   * Constructor predicate to bind this instance to local variables that are parameters.
   */
  Parameter() { lvars(this, _, _, true, _) }

  /**
   * Gets an access to this parameter.
   */
  override ParameterVariableAccess getAnAccess() { result.getTarget() = this }

  /**
   * Returns a string representation including the local variable's type and name.
   */
  override string toString() { result = "Parameter " + this.getType() + " " + this.getName() + " in " + this.getFunction() }
}

/**
 * Represents a global variable declared at global scope.
 */
class GlobalVariable extends Variable, @gvar {
  /**
   * Constructor predicate to bind this instance to known global variables.
   */
  GlobalVariable() { gvars(this, _, _) }

  /**
   * Returns a string representation of the global variable.
   */
  override string toString() { result = "GlobalVariable " + this.getType() + " " + this.getName() }

  /**
   * Gets the name of the global variable.
   */
  override string getName() { gvars(this, result, _) }

  /**
   * Holds if the GlobalVariable has name `name`.
   */
  override predicate hasName(string name) { this.getName() = name }

  /**
   * Gets the type of the global variable.
   */
  override Type getType() { gvars(this, _, result) }

  /**
   *  Gets an access to this global variable.
   */
  override GlobalVariableAccess getAnAccess(){
    result.getTarget() = this
  }
}
