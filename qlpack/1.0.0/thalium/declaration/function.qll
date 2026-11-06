/**
 * Provides a representation of functions defined in source code.
 *
 */

import binary

/**
 * Represents a function in the source code.
 *
 * Functions can be called, declared, and have a body (block) associated with them.
 */
class Function extends @function {
  /**
   * Constructor predicate to bind this instance to known functions.
   */
  Function() { functions(this, _, _, _) }

  /**
   * Gets the name of the function.
   */
  string getName() { functions(this, result, _, _) }

  /**
   * Holds if the Function has name `name`.
   */
  predicate hasName(string name) { this.getName() = name }

  /**
   * Holds if this function is imported from another module (its code is not in the binary).
   *
   * The extractor names imported functions with an `ext_` prefix, for example `ext_memcpy`.
   */
  predicate isExternal() { this.getName().matches("ext\\_%") }

  /**
   * Gets the name of the function without the `ext_` prefix of imported functions,
   * for example `memcpy` for `ext_memcpy`. Same as `getName()` for other functions.
   */
  string getBaseName() { result = this.getName().regexpReplaceAll("^ext_", "") }

  /**
   * Holds if the function has base name `name`, see `getBaseName()`.
   */
  predicate hasBaseName(string name) { this.getBaseName() = name }

  /**
   * Gets the type of the function.
   */
  Type getType() { functions(this, _, result, _) }

  /**
   * Gets the source location of the function.
   */
  Location getLocation() { functions(this, _, _, result) }

  /**
   * Returns a string representation including the function name and location.
   */
  string toString() { result = "Function " + this.getName() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  string debug() { result = "Function " + this.getName() + " at " + this.getLocation() }

  /**
   * Gets the body block associated with this function.
   */
  BlockStmt getBlock() {
    function_bodys(this, result)
  }

  /** Gets a call to this function. */
  FunctionCall getACallToThisFunction() { result.getTarget() = this }

  /** Holds if this function calls the function `callee`. */
  predicate calls(Function callee) {
    exists(
      FunctionCall call |
      this.getBlock() = call.getEnclosingBlock() and
      call.getTarget() = callee)
  }
}

/**
 * A function imported from another module, such as a libc function called through the PLT.
 */
class ExternalFunction extends Function {
  ExternalFunction() { this.isExternal() }
}
