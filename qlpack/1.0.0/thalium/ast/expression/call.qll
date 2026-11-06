/**
 * Provides representations of C/C++ function calls and their arguments.
 *
 * This file defines the QL classes for modeling function call expressions in C/C++:
 * - `Call`: The base class for all call expressions.
 * - `FunctionCall`: Calls where the target function is known at compile-time, including
 *   direct function calls, member function calls, and decompiler intrinsics.
 * - `CallArgument`: Represents an argument passed to a function call, including its index
 *   and parent call.
 *
 * Each class provides methods to obtain a textual representation and to access
 * associated metadata such as function names, arguments, and targets.
 */

import binary

/**
 * A C/C++ call.
 */
class Call extends Expression, @ens_call {
  /**
   * Gets a textual representation of this expression.
   */
  override string toString() { result = "Call" }

/**
 * Returns a debug-friendly string representation of the statement.
 */
  override string debug() { result = "Call " + this.getLocation() }
}

/**
 * A C/C++ function call where the name of the target function is known at compile-time.
 *
 * This includes various kinds of call:
 *  1. Calls such as `f(x)` where `f` is the name of a function.
 *  2. Calls such as `ptr->f()` where `f` is the name of a (possibly virtual) member function.
 *  3. Calls such as `<Decompiler intrinsic>()` where `<Decompiler intrinsic>` is function made
 *
 * by the decompiler to abstract some pseudo-code/(assembly as `asm()` in Pseudo-Code).
 *
 * See: [Hexrays - Support for intrinsic functions](https://docs.hex-rays.com/user-guide/decompiler/intrinsics)
 */
final class FunctionCall extends Call, @function_calls {
  /**
   * Gets the name of the function being called.
   */
  string getName() {
    result = this.getTarget().getName()
  }

  /**
   * Holds if the FunctionCall has name `name`.
   */
  predicate hasName(string name) { this.getName() = name }

  /**
   * Gets the target function object for this call.
   */
  Function getTarget() {
    function_calls(this, result, _)
  }

  /**
   * Gets the target function object for this call.
   */
  boolean isRealFunction() {
    function_calls(this, _, result)
  }

  /**
   * Gets a textual representation of this expression.
   */
  override string toString() {
    result = "FunctionCall to " + this.getTarget()
  }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() {
    result = "FunctionCall to " + this.getTarget() + " at " + this.getLocation().toString()
  }

  /**
   * Returns the number of arguments passed to the function call.
   */
  int getNumberOfArguments() {
    result = count(CallArgument arg | arg.getCall() = this)
  }

  /**
   * Gets the nth argument (0-based) passed to the function call.
   */
  CallArgument getArgument(int index) {
    result = this.getChild(index)
  }

  /**
   * Gets any argument associated with this function call.
   */
  CallArgument getArguments() {
    result = any(CallArgument arg | arg.getCall() = this)
  }
}

/**
 * A C/C++ function's argument.
 *
 * Here, **`a`**, **`b + 1`**, and **`s->m`** are CallArgument.
 * ```
 * f(a, b + 1, s->m);
 * ```
 */
class CallArgument extends Node {
  /**
   * Gets the function call this argument belongs to.
   */
  FunctionCall getCall() {
    exists(int i |
      result = any(FunctionCall fc | fc.getArgument(i) = this)
    )
  }


  /**
   * Gets the index of this argument in the argument list (0-based).
   */
  int getIndex() { call_args(this, _, result) }

  /**
   * Gets a textual representation of this expression.
   */
  override string toString() {
    result = "CallArg n°" + this.getIndex() + " of " + this.getCall().toString()
  }
}
