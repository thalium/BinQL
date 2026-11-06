/**
 * Provides a representation of source-level nodes and statements.
 *
 */

import binary

/**
 * Represents a statement in the source code.
 *
 * Statements correspond to syntactic constructs that perform actions or control flow,
 * such as expressions, declarations, or control statements (e.g., if, for).
 */
class Node extends @node {
  /**
   * Returns a string representation of the statement.
   */
  string toString() { result = "Node" + getLocation() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  string debug() { result = "Node" + getLocation() }

  /**
   * Returns the primary QL class name for this entity.
   */
  string getAPrimaryQlClass() { result = "Node" }

  /**
   * Gets the source code location of this statement.
   */
  Location getLocation() { nodes(this, result, _) }

  /**
   * Returns the start address of the statement's location as a hexadecimal string.
   */
  string getEA() { result = "0x" + toHex(this.getLocation().getStart()) }

  /**
   * Returns an integer representing the kind of statement.
   *
   * This can be used to distinguish between different statement types.
   *
   * Internals
   */
  int getKind() { nodes(this, _, result) }

  // --- Parent / Child Relationships ---

  /**
   * Gets the parent statement of this statement, if any.
   *
   * Statements are often nested; this returns the immediate containing statement.
   */
  Node getParent() { parents(result, this, _) }

  /**
   * Gets a child statement of this statement.
   *
   * Useful for traversing nested statements or blocks.
   */
  Node getAChild() { parents(this, result, _) }

  /**
   * Gets the nth child node of this node.
   *
   * @param index The 0-based index of the child to retrieve.
   * @return The child node at index {@code index}, if it exists.
   */
  Node getChild(int index) { parents(this, result, index) }

  /**
   * Gets the leftmost child node of this node, if there is more than one child.
   */
  Node getLeftChild() {
    result = getChild(0) and count(getAChild()) > 1
  }

  /**
   * Gets the rightmost child node of this node.
   */
  Node getRightChild() {
    result = getChild(1) and count(getAChild()) = 2
    or
    result = getChild(2) and count(getAChild()) = 3
  }

  /**
   * Gets the middle child node of this node, if it has exactly three children.
   */
  Node getMiddleChild() {
    result = getChild(1) and count(getAChild()) = 3
  }

  /**
   * Gets the enclosing function for this statement.
   *
   * Traverses parent blocks until a function containing this statement is found.
   */
  Function getEnclosingFunction() {
    result = this.getParent*().(BlockStmt).getFunction()
  }

  /**
   * Gets the enclosing block containing this statement.
   *
   * If the immediate parent is a block, returns it; otherwise, recurses up the
   * parent chain until a block is found.
   */
  BlockStmt getEnclosingBlock() {
    if this.getParent() instanceof BlockStmt
    then result = this.getParent()
    else result = this.getParent().getEnclosingBlock()
  }

  // --- Subtree visualization ---

  /**
   * Gets a multi-line, indented rendering of this node's whole subtree — one line per
   * descendant (including this node), each showing its own `getAPrimaryQlClass()` and
   * `toString()`, ordered as AST pre-order and indented by depth.
   *
   * Meant as a debugging aid for exploring an unfamiliar node's real child layout instead of
   * guessing `getChild(n)` indices by hand.
   */
  string prettyPrint() {
    result =
      concat(Node n, string p |
        p = path(this, n)
      |
        indent(depth(p)) + n.getAPrimaryQlClass() + ": " + n.toString() + "\n" order by p
      )
  }
}

/**
 * Gets a zero-padded, dot-joined child-index path from `root` down to `n` (`""` when
 * `n = root`). Every recursive step is guarded by `n = root.getAChild+()`, so evaluation only
 * ever unfolds along real subtree edges of `root` and never touches unrelated nodes elsewhere
 * in the database. String ordering of the result matches AST pre-order.
 */
private string path(Node root, Node n) {
  n = root and result = ""
  or
  n = root.getAChild+() and
  exists(Node parent, int idx | parent = n.getParent() and parents(parent, n, idx) |
    parent = root and result = pad3(idx)
    or
    parent != root and result = path(root, parent) + "." + pad3(idx)
  )
}

/** Gets `i` zero-padded to (at least) 3 digits. */
bindingset[i]
private string pad3(int i) {
  i in [0 .. 9] and result = "00" + i.toString()
  or
  i in [10 .. 99] and result = "0" + i.toString()
  or
  i >= 100 and result = i.toString()
}

/**
 * Gets the depth of a `path()` result below its root — `0` for the root itself (`p = ""`),
 * otherwise the number of `.` separators plus one.
 */
bindingset[p]
private int depth(string p) {
  p = "" and result = 0
  or
  p != "" and result = count(int i | p.charAt(i) = ".") + 1
}

/** Gets `depth` levels of two-space indentation. */
bindingset[depth]
private string indent(int depth) { result = concat(int i | i = [1 .. depth] | "  ") }
