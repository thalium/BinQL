/**
 * Provides a representation of source code locations within a binary.
 *
 */

import binary

/**
 * Represents a source code location within a binary, defined by start and end offsets.
 *
 * For example, a location might indicate the byte range within a compiled binary
 * corresponding to a particular statement or expression in source code.
 */
class Location extends @location {
  /**
   * Returns a string representation of the location, including its start address in hexadecimal
   * and the binary file it belongs to.
   */
  string toString() { result = "0x" + toHex(this.getStart()) + "@" + this.getBinary() }

  /**
   * Gets the binary file associated with this location.
   */
  string getBinary() { locations(this, result, _, _) }

  /**
   * Gets the starting offset (in bytes) of this location within the binary.
   */
  float getStart() { locations(this, _, result, _) }

  /**
   * Gets the ending offset (in bytes) of this location within the binary.
   */
  int getEnd() { locations(this, _, _, result) }
}
