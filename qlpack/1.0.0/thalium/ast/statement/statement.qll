/**
 * Provides representations of C/C++ statements and control structures.
 *
 */

import binary

/**
 * A C/C++ statement.
 */
class Statement extends Node, @ens_stmt {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "Statement" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "Statement " + this.getLocation() }
}

/**
 * A C/C++ 'empty' statement.
 *
 * For example, a function without pseudo-code, like external functions.
 * ```
 *           
 * ```
 */
final class EmptyStmt extends Statement, @emptyblockstmts {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "EmptyStmt" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "EmptyStmt " + this.getLocation() }
}

/**
 * A C/C++ block statement.
 *
 * For example, the block from `{` to `}` in the following code:
 * ```
 * {
 *   int a;
 *   int b = 1;
 *   a = b;
 * }
 * ```
 */
final class BlockStmt extends Statement, @blockstmts {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "BlockStmt" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "BlockStmt " + this.getLocation() }

  /**
   * Gets the function that contains this block.
   */
  Function getFunction() { function_bodys(result, this) }

  /**
   * Gets a multi-line rendering of this block's full contents — every nested node's own
   * `toString()`, indented by depth — instead of just the bare "BlockStmt" class name.
   * Delegates to `Node.prettyPrint()`.
   */
  string display() { result = this.prettyPrint() }
}

/**
 * A C/C++ code line.
 *
 * ```
 * ...;
 * ```
 */
final class ExpressionStmt extends Statement, @exprstmts {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "ExpressionStmt " + this.getChild(0) }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "ExpressionStmt " + this.getChild(0) + " at " + this.getLocation() }
}

/**
 * A C/C++ control structure, that is, either a conditional statement or a loop.
 */
class ControlStructure extends Statement, @ens_controlstructure {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "ControlStructure" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "ControlStructure " + this.getLocation() }
}

/**
 * A C/C++ conditional statement, that is, either an ‘if’ statement or a ‘switch’ statement.
 */
class ConditionalStmt extends ControlStructure, @ens_conditionalstmt {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "ConditionalStmt" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "ConditionalStmt " + this.getLocation() }

  /**
   * Gets the condition expression of this conditional statement.
   */
  Node getCondition() {
    if count(this.getAChild()) = 3
    then result = this.getChild(2)
    else result = this.getChild(1)
  }
}

/**
 * A C/C++ 'if' statement.
 *
 * ```
 * if (x == 1) {
 *   ...
 * }else {
 *   ...
 * }
 * ```
 */
final class IfStmt extends ConditionalStmt, @ifstmts {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "IfStmt" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "IfStmt " + this.getLocation() }

  /**
   * Gets the 'then' branch of this 'if' statement.
   */
  Node getThen() { result = this.getChild(0) }

  /**
   * Gets the condition of this 'if' statement.
   */
  // The condition is always the last child: index 1 with no else, index 2 with one.
  override Node getCondition() {
    exists(int n | n = count(this.getAChild()) - 1 and result = this.getChild(n))
  }

  /**
   * Holds if this 'if' statement has an 'else' branch.
   */
  predicate hasElse(){ exists(this.getElse()) }

  /**
   * Gets the 'else' branch of this 'if' statement.
   */
  Node getElse() {
    count(this.getAChild()) = 3 and
    result = this.getChild(1)
  }
}

/**
 * A C/C++ 'switch' statement.
 *
 * ```
 * switch (i)
 * {
 * case 5:
 *   ...
 * default:
 *   ...
 * }
 * ```
 */
final class SwitchStmt extends ConditionalStmt, @switchstmts {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "SwitchStmt" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "SwitchStmt " + this.getLocation() }

  /**
   * Gets a case (or default) branch of this 'switch' statement.
   */
  SwitchCase getASwitchCase() { result.getSwitchStmt() = this }

  /**
   * Gets the 'default' branch of this 'switch' statement, if any.
   */
  SwitchCase getDefaultCase() { result = this.getASwitchCase() and result.isDefault() }

  /**
   * Gets the number of case/default branches in this 'switch' statement.
   */
  int getNumberSwitches() { result = count(this.getASwitchCase()) }

  /**
   * Gets the controlling expression of this 'switch' statement.
   */
  Node getControllingExpr() {
    result = this.getAChild() and not result instanceof SwitchCase
  }
}

/**
 * A C/C++ 'case' or 'default' branch of a 'switch' statement.
 *
 * Hex-Rays has no separate case label node: a `SwitchCase` is the case's body
 * statement itself. Consecutive labels sharing a body (`case 1: case 2:`) are
 * merged into one `SwitchCase` with several values.
 */
class SwitchCase extends Node {
  @switch_case id;

  /**
   * Constructor predicate to bind this instance to a case/default child of a 'switch' statement.
   */
  SwitchCase() {
    exists(SwitchStmt s, int i |
      switch_cases(id, s, _, i) and
      this = s.getChild(i)
    )
  }

  /**
   * Gets the 'switch' statement this case belongs to.
   */
  SwitchStmt getSwitchStmt() { switch_cases(id, result, _, _) }

  /**
   * Gets the position of this case among the cases of its 'switch' statement.
   */
  int getIndex() { switch_cases(id, _, result, _) }

  /**
   * Gets a value matched by this case, as an exact signed decimal string.
   * Has no result for 'default'.
   */
  string getAValue() { switch_case_values(id, result) }

  /**
   * Holds if this is the 'default' branch.
   */
  predicate isDefault() { not switch_case_values(id, _) }

  /**
   * Gets the index of this case among the children of its 'switch' statement.
   */
  int getChildNum() {
    parents(this.getParent(), this, result)
  }

  /**
   * Gets the case immediately following this one in the same 'switch' statement.
   */
  SwitchCase getNextSwitchCase() {
    result.getSwitchStmt() = this.getSwitchStmt() and
    result.getIndex() = this.getIndex() + 1
  }

  /**
   * Gets the case immediately preceding this one in the same 'switch' statement.
   */
  SwitchCase getPreviousSwitchCase() {
    result.getSwitchStmt() = this.getSwitchStmt() and
    result.getIndex() = this.getIndex() - 1
  }
}


/**
 * A C/C++ loop, that is, either a 'while' loop, a 'for' loop, or a 'do' loop.
 */
class Loop extends ControlStructure, @ens_loop {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "Loop" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "Loop " + this.getLocation() }
}

/**
 * A C/C++ 'do' statement.
 *
 * ```
 * do {
 *     ...
 * } while (...);
 * ```
 */
final class DoStmt extends Loop, @dostmts {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "DoStmt" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "DoStmt " + this.getLocation() }

  /**
   * Gets the body statement of this 'do' loop.
   */
  Statement getStmt() { result = this.getChild(0) }
  /**
   * Gets the condition of this 'do' loop.
   */
  Node getCondition() { result = this.getChild(1) }
}

/**
 * A C/C++ 'for' statement.
 *
 * Only represents traditional 'for' loops, not C++11 range-based 'for' loops.
 *
 * ```
 * for (i = 0; i < 10; i++) { j++; }
 * ```
 */
final class ForStmt extends Loop, @forstmts {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "ForStmt" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "ForStmt " + this.getLocation() }

  /**
   * Gets the initialization expression of this 'for' loop.
   */
  Expression getInitialization() { result = this.getChild(0) }
  /**
   * Gets the condition expression of this 'for' loop.
   */
  Expression getCondition() { result = this.getChild(3) }
  /**
   * Gets the update expression of this 'for' loop.
   */
  Expression getUpdate() { result = this.getChild(1) }
  /**
   * Gets the body statement of this 'for' loop.
   */
  Statement getStmt() { result = this.getChild(2) }
  /**
   * Gets the variable assigned in the initialization of this 'for' loop.
   */
  Variable getAnIterationVariable() { result = this.getInitialization().(AssignExpr).getLeftChild().(VariableAccess).getTarget() }
}

/**
 * A C/C++ 'while' statement.
 *
 * ```
 * while (...) {
 *   ...
 * }
 * ```
 */
final class WhileStmt extends Loop, @whilestmts {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "WhileStmt" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "WhileStmt " + this.getLocation() }

  /**
   * Gets the body statement of this 'while' loop.
   */
  Statement getStmt() { result = this.getChild(0) }
  /**
   * Gets the condition of this 'while' loop.
   */
  Node getCondition() { result = this.getChild(1) }
}

/**
 * A C/C++ jump statement.
 */
class JumpStmt extends Statement, @ens_jumpstmt {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "JumpStmt" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "JumpStmt " + this.getLocation() }
}

/**
 * A C/C++ 'break' statement.
 *
 * ```
 * while (x) {
 *   if (arr[x] == 0) break;
 *   ...
 * }
 * ```
 */
final class BreakStmt extends JumpStmt, @breakstmts {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "BreakStmt" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "BreakStmt " + this.getLocation() }
}

/**
 * A C/C++ 'continue' statement.
 *
 * ```
 * while (x) {
 *   if (arr[x] < 0) continue;
 *   ...
 * }
 * ```
 */
final class ContinueStmt extends JumpStmt, @continuestmts {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "ContinueStmt" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "ContinueStmt " + this.getLocation() }
}

/**
 * A C/C++ 'return' statement.
 *
 * ```
 * return 1+2;
 * ```
 * or
 * ```
 * return;
 * ```
 */
final class ReturnStmt extends JumpStmt, @returnstmts {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "Return " + this.getTarget() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "Return " + this.getTarget() + " at " + this.getLocation() }

  /**
   * Returns the target expression or statement being returned.
   */
  Node getTarget() { result = this.getChild(0) }
}

/**
 * A C/C++ 'goto' statement.
 *
 * ```
 * goto someLabel;
 * ...
 * somelabel:
 * ```
 */
final class GotoStmt extends JumpStmt, @gotostmts {
  /**
   * Constructor predicate to bind this instance to known 'goto' statements.
   */
  GotoStmt() {
    gotostmts(this, _, _)
  }

  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "GotoStmt to " + this.getName() }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "GotoStmt " + this.getLocation() }

  /**
   * Gets the label this 'goto' statement jumps to.
   */
  LabelStmt getLabel() { gotostmts(this, result, _) }

  /**
   * Gets the name of the target label.
   */
  string getName() { gotostmts(this, _, result) }
}

/**
 * A C/C++ 'try' statement.
 *
 * ```
 * try {
 *   ...
 * } catch (int e) {
 *   ...
 * }
 * ```
 *
 * Only reconstructed by Hex-Rays from MSVC's own C++ EH tables; GCC/Itanium-ABI
 * `__cxa_throw` call sequences never produce this node.
 *
 * Deliberately not shaped like the standard CodeQL C++ library's `TryStmt`,
 * whose `getStmt()` returns a single `BlockStmt` for the tried body: Clang's
 * AST wraps `try { ... }` in one compound-statement node, but `ctry_t` has no
 * equivalent wrapper -- Hex-Rays flattens the tried statements, every catch
 * handler's body, and each handler's caught-object expression into one
 * undifferentiated child list on this node, in that order. Use
 * `getATriedStmt()` rather than `getChild()` directly to isolate the tried
 * part; see `CatchBlock` for the rest.
 */
final class TryStmt extends Statement, @cit_trys {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "TryStmt " + this.getChild(0) }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = this.toString() + this.getLocation() }

  /**
   * Number of children (from index 0) that belong to the tried block, before
   * the first catch handler's children begin.
   */
  int getTriedBodyLength() { trystmts(this, result) }

  /**
   * Gets a statement belonging to the tried block (as opposed to a catch
   * handler's body or a caught-object expression).
   */
  Node getATriedStmt() {
    exists(int i | i < this.getTriedBodyLength() and result = this.getChild(i))
  }

  /**
   * Gets a catch clause of this try statement.
   */
  CatchBlock getACatchClause() { result.getTryStmt() = this }

  /**
   * Gets the `n`th catch clause of this try statement, in source order.
   */
  CatchBlock getCatchClause(int n) {
    result = this.getACatchClause() and result.getIndex() = n
  }

  /**
   * Gets the number of catch clauses of this try statement.
   */
  int getNumberOfCatchClauses() { result = count(this.getACatchClause()) }
}

/**
 * A single `catch` clause of a `TryStmt`, named to match the standard CodeQL
 * C++ library's `CatchBlock`. Structurally it isn't one: Hex-Rays gives it no
 * `citem_t`/ctree opcode of its own (there is no `cit_catch`, unlike Clang's
 * `CXXCatchStmt`), so it can't extend `BlockStmt`/`Node` the way the standard
 * library's does -- it only exists as a sub-structure of `ctry_t`, reachable
 * in the extractor via `i.ctry.catchs`, not through the ordinary per-node
 * traversal. See `CatchAnyBlock` for `catch (...)`.
 */
class CatchBlock extends @catch_handler {
  /**
   * Gets a textual representation of this catch clause.
   */
  string toString() { result = "CatchBlock" }

  /**
   * Gets the try statement this clause belongs to.
   */
  TryStmt getTryStmt() { catch_handlers(this, result, _, _, _) }

  /**
   * Gets this clause's 0-based position among its try statement's catch
   * clauses, in source order.
   */
  int getIndex() { catch_handlers(this, _, result, _, _) }

  /**
   * Holds if this is a catch-all clause (`catch (...)`), with no bound
   * exception object.
   */
  predicate isCatchAll() { not exists(this.getParameter()) }

  /**
   * Gets the exception object bound by this clause, e.g. `e` in
   * `catch (int e)`. No result for a catch-all clause.
   */
  Node getParameter() {
    exists(int i | catch_handler_params(this, i, _) and result = this.getTryStmt().getChild(i))
  }

  /**
   * Gets the type of the exception object this clause catches. No result
   * for a catch-all clause.
   */
  Type getCaughtType() { catch_handler_params(this, _, result) }

  /**
   * Gets a statement belonging to this clause's body.
   */
  Node getABodyStmt() {
    exists(int start, int len, int i |
      catch_handlers(this, _, _, start, len) and
      i in [start .. start + len - 1] and
      result = this.getTryStmt().getChild(i)
    )
  }
}

/**
 * A catch-all clause, `catch (...)`.
 */
class CatchAnyBlock extends CatchBlock {
  /**
   * Constructor predicate to bind this instance to catch-all clauses.
   */
  CatchAnyBlock() { this.isCatchAll() }
}

/**
 * A C/C++ 'throw' statement.
 *
 * ```
 * throw x;
 * ```
 *
 * See `TryStmt` for the same MSVC-ABI-only caveat.
 */
final class ThrowStmt extends Statement, @cit_throws {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "ThrowStmt " + this.getChild(0) }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = this.toString() + this.getLocation() }
}

/**
 * An inline assembly block: instructions Hex-Rays left undecompiled.
 *
 * ```
 * __asm { fninit fnclex }
 * ```
 *
 * Hex-Rays only emits it for instructions it has no intrinsic for
 * most "special" ones (`cli`, `wfi`, `sync`, ...) become `cot_helper` calls instead.
 */
final class AsmStmt extends Statement, @cit_asms {
  /**
   * Gets a textual representation of this statement.
   */
  override string toString() { result = "AsmStmt" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  override string debug() { result = "AsmStmt " + this.getLocation() }

  /**
   * Gets the primary QL class name for this statement.
   */
  override string getAPrimaryQlClass() { result = "AsmStmt" }

  /**
   * Gets the `index`th instruction of this block (0-based, in address order).
   */
  AsmInstruction getInstruction(int index) {
    result.getAsmStmt() = this and result.getIndex() = index
  }

  /**
   * Gets an instruction of this block.
   */
  AsmInstruction getAnInstruction() { result.getAsmStmt() = this }

  /**
   * Gets the number of instructions in this block.
   */
  int getNumberOfInstructions() { result = count(this.getAnInstruction()) }

  /**
   * Gets this block's instructions on one line, the way Hex-Rays prints it,
   * e.g. `__asm { fninit; fnclex }`. IDA's column spacing is collapsed.
   */
  string display() {
    result =
      "__asm { " +
        concat(AsmInstruction insn, int i |
          insn = this.getInstruction(i)
        |
          insn.getText().regexpReplaceAll("\\s+", " "), "; " order by i
        ) + " }"
  }
}

/**
 * A single machine instruction of an `AsmStmt`. Not a `Node`: Hex-Rays keeps
 * only its address (`cinsn_t.casm`), mnemonic and text come from the IDA
 * database.
 */
class AsmInstruction extends @asm_insn {
  /**
   * Gets a textual representation of this instruction: its disassembly line.
   */
  string toString() { result = this.getText() }

  /**
   * Gets the asm block this instruction belongs to.
   */
  AsmStmt getAsmStmt() { asm_stmt_insns(this, result, _, _, _, _) }

  /**
   * Gets this instruction's 0-based position in its block.
   */
  int getIndex() { asm_stmt_insns(this, _, result, _, _, _) }

  /**
   * Gets the address of this instruction.
   */
  float getAddress() { asm_stmt_insns(this, _, _, result, _, _) }

  /**
   * Gets the address of this instruction as a hex string, e.g. `0x112d`.
   */
  string getEA() { result = "0x" + toHex(this.getAddress()) }

  /**
   * Gets the mnemonic of this instruction, as IDA prints it (e.g. `fninit`, `MSR`).
   */
  string getMnemonic() { asm_stmt_insns(this, _, _, _, result, _) }

  /**
   * Gets the full disassembly line of this instruction, e.g. `MSR DAIFSet, #2`
   * (IDA's own column spacing kept).
   */
  string getText() { asm_stmt_insns(this, _, _, _, _, result) }
}

final class LabelStmt extends @label {
  /**
   * Constructor predicate to bind this instance to known labels.
   */
  LabelStmt() { labels(this, _) }
  /**
   * Gets a textual representation of this statement.
   */
  string toString() { result = "Label" }

  /**
   * Returns a debug-friendly string representation of the statement.
   */
  string debug() { result = "Label" }

  /**
   * Gets the node this label is attached to.
   */
  Node getNode() { labels(this, result) }
}
