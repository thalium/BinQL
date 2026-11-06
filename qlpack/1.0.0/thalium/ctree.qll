/**
 * Provides a representation of object and variable declarations in source code.
 *
 */

import binary

/**
 * Represents an object or variable declaration in the source code.
 */
class Object extends Node, @cot_objs {
  /**
   * Returns a string describing the object's type and name.
   */
  override string toString() {
    result = "Object " + this.getType() + " " + this.getName()
  }

  /**
   * Gets the name of the object.
   */
  string getName() { cot_objs(this, result, _) }

  /**
   * Holds if the Object has name `name`.
   */
  predicate hasName(string name) { this.getName() = name }

  /**
   * Gets the type of the object.
   */
  string getType() { cot_objs(this, _, result) }
}
