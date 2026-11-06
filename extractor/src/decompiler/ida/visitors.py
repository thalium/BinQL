import os
import sys

import ida_hexrays
import ida_lines
import ida_pro
import idaapi

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

from decompiler.ida.utils import Context, cit_generic_cases, cot_generic_cases
from utils.constants import BADADDR_IDA, cot_and_cit
from utils.logger import TrapLogger
from utils.trap import trap_generator_t


class global_visitor_t(ida_hexrays.ctree_visitor_t):
    """Collect names of globals referenced by a function into `ctx.gvars`.

    `refwidth > 0` excludes string literals (refwidth == -1) and zero-sized refs;
    the lvar-name check excludes lvars/params that shadow a global name.
    """

    def __init__(self, ctx: "Context") -> None:
        """Snapshot the function's lvar names for the shadowing check."""
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.ctx = ctx
        self._lvar_names: set[str] = {lvar.name for lvar in ctx.cfunc.get_lvars()}

    def visit_insn(self, i: ida_hexrays.cinsn_t) -> int:
        """No-op: only `cot_obj` expressions matter."""
        return 0

    def visit_expr(self, e: ida_hexrays.cexpr_t) -> int:
        """Add a `cot_obj`'s printed name to `ctx.gvars` if it is a non-local data ref."""
        if cot_and_cit[e.op] != "cot_obj":
            return 0

        # Extract a cleaned-up string representation of the expression
        current_var_name = ida_pro.str2user(
            ida_lines.tag_remove(e.print1(None))
        ).replace('\\"', "'")
        is_local_variable = current_var_name in self._lvar_names

        if e.refwidth > 0 and e.ea != idaapi.BADADDR and not is_local_variable:
            self.ctx.gvars.add(current_var_name)

        return False


class ctree_visitor_t(ida_hexrays.ctree_visitor_t):
    def __init__(self, ctx: "Context", function_name):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
        self.trap_generator = trap_generator_visitor_t(ctx, self)
        self.ctx = ctx
        self.logger = TrapLogger.from_env()

    def flush(self) -> None:
        self.trap_generator.flush()

    def _guarded(self, kind: str, item) -> int:
        """Dispatch one node, logging and counting a handler exception instead of raising.

        A raise would reach `analysis.analyse_function`'s `except`, which discards every
        buffered trap for the function; an incomplete subtree beats a missing function.
        """
        try:
            if kind == "cit":
                self.trap_generator.handler_cit(item)
            else:
                self.trap_generator.handler_cot(item)
        except Exception as exc:
            self.ctx.dropped_nodes += 1
            op = cot_and_cit[item.op] if 0 <= item.op < len(cot_and_cit) else item.op
            try:
                ea = hex(int(item.ea))
            except Exception:
                ea = "?"
            self.logger.error(
                f"NODE_DROPPED {kind} op={op} ea={ea} "
                f"fn={self.ctx.curr_fn_name}: {exc!r}"
            )
        return 0

    def visit_insn(self, i: ida_hexrays.cinsn_t) -> int:
        """Emit traps for an instruction node."""
        return self._guarded("cit", i)

    def visit_expr(self, e: ida_hexrays.cexpr_t) -> int:
        """Emit traps for an expression node."""
        return self._guarded("cot", e)


class trap_generator_visitor_t(ida_hexrays.ctree_visitor_t):
    """Trap emission for `ctree_visitor_t`: node/location/edge traps and op dispatch."""

    def __init__(self, ctx, binql_visitor):
        # Local import to avoid the circular dependency with handler_dispatcher_t
        from handlers import handler_dispatcher_t

        self.ctx = ctx
        self.binql_visitor = binql_visitor

        self.trap_generator = trap_generator_t(self.ctx)
        self.ids = {"locations": 0, "statements": 0}
        self.logger = TrapLogger.from_env()
        self.relations: dict[int, int] = {}
        self.child_number = {}

        binql_target = os.environ.get("BINQL_TARGET")
        if binql_target is None:
            raise RuntimeError("BINQL_TARGET environment variable is not set")
        self.binary_name = os.path.basename(binql_target)

        self.handler_dispatcher = handler_dispatcher_t(self.ctx, self)

    def write_trap(self, kind: str, trap: str):
        """Write `trap` to `<kind>.trap`."""
        self.trap_generator.write_trap(kind, trap)

    def flush(self) -> None:
        self.trap_generator.flush()

    def is_root(self, citem: ida_hexrays.citem_t) -> bool:
        return not any(p is not None for p in self.binql_visitor.parents)

    def get_parent(self, citem: ida_hexrays.citem_t):
        """Return the visitor's current innermost parent, or None at the root (`citem` is unused)."""
        if self.is_root(citem):
            return None  # Block, no parent
        if self.get_parents(citem):
            return self.binql_visitor.parents.at(len(self.binql_visitor.parents) - 1)
        return None

    def get_trap_id_by_citem(self, citem: ida_hexrays.citem_t | None) -> int | None:
        if citem is None:
            return None
        return self.relations.get(int(citem.this))

    def get_parents(self, citem: ida_hexrays.citem_t):
        return self.binql_visitor.parents

    def handler_cit(self, i: ida_hexrays.cinsn_t):
        """Dispatch an instruction node to its handler, then emit its label if any."""
        value = cot_and_cit[i.op]

        match value:
            case _ if value in cit_generic_cases:
                self.handler_dispatcher.generic(i)
            case "cit_block":
                self.handler_dispatcher.cit_block(i)
            case "cit_expr":
                self.handler_dispatcher.cit_expr(i)
            case "cit_goto":
                self.handler_dispatcher.cit_goto(i)
            case "cit_switch":
                self.handler_dispatcher.cit_switch(i)
            case "cit_try":
                self.handler_dispatcher.cit_try(i)
            case "cit_throw":
                self.handler_dispatcher.cit_throw(i)
            case "cit_asm":
                self.handler_dispatcher.cit_asm(i)
            case _:
                self.handler_dispatcher.missing(i)

        # Add a label information if there is one
        self.handler_dispatcher.cot_label(i)

    def handler_cot(self, e):
        """Dispatch an expression node to its handler."""
        value = cot_and_cit[e.op]

        match value:
            case _ if value in cot_generic_cases:
                self.handler_dispatcher.generic(e)
            case "cot_cast":
                self.handler_dispatcher.cot_cast(e)
            case "cot_ptr":
                self.handler_dispatcher.cot_ptr(e)
            case "cot_call":
                self.handler_dispatcher.cot_call(e)
            case "cot_memref":
                self.handler_dispatcher.cot_memref(e)
            case "cot_memptr":
                self.handler_dispatcher.cot_memptr(e)
            case "cot_num":
                self.handler_dispatcher.cot_num(e)
            case "cot_fnum":
                self.handler_dispatcher.cot_fnum(e)
            case "cot_str":
                self.handler_dispatcher.cot_str(e)
            case "cot_obj":
                self.handler_dispatcher.cot_obj(e)
            case "cot_var":
                self.handler_dispatcher.cot_var(e)
            case "cot_sizeof":
                self.handler_dispatcher.cot_sizeof(e)
            case "cot_helper":
                # cot_handler are handled while in their parent, a cot_call
                pass
            case _:
                self.handler_dispatcher.missing(e)

    # Trap specific

    def generate_location(self, binary: str, e: ida_hexrays.citem_t) -> int:
        """Emit a location at the innermost ancestor with a valid EA, else at `e`'s EA."""
        candidat: ida_hexrays.citem_t = next(
            (
                p
                for p in reversed(list(self.binql_visitor.parents))
                if p is not None and p.ea != BADADDR_IDA
            ),
            e,
        )
        start = candidat.ea
        end = candidat.ea

        return self.trap_generator.generate_location(
            self.ctx.curr_fn_name, binary, start, end
        )

    def generate_node(
        self, loc: int, citem: ida_hexrays.citem_t, node_type: int | None = None
    ) -> int:
        """Emit a `nodes` trap (type defaults to `citem.op`) and record its id in `relations`."""
        node_id = self.ctx.increment_global_id()
        node_type = node_type if node_type is not None else citem.op
        trap = f"nodes({node_id}, {loc}, {node_type})"

        # Track the item's global ID for later reference
        self.relations[int(citem.this)] = node_id

        if not self.is_root(citem):
            parent_id = self.get_trap_id_by_citem(self.get_parent(citem))
            self.child_number[parent_id] = self.child_number.get(parent_id, -1) + 1

        trap_log = f"nodes({node_id}, {loc}, {node_type} ({cot_and_cit[node_type]}))"
        self.write_trap(self.ctx.curr_fn_name, trap)
        self.logger.trap(trap_log + "\n")
        return node_id

    def generate_edge(self, child: ida_hexrays.citem_t):
        """Emit the `parents` edge for `child`; skipped if the parent has no trap id."""
        parent = self.get_parent(child)
        child_id = self.get_trap_id_by_citem(child)
        parent_id = self.get_trap_id_by_citem(parent)

        # Emit parent-child edge if applicable
        if parent_id is not None:
            index = self.child_number.get(parent_id, 0)
            trap = f"parents({parent_id}, {child_id}, {index})"
            self.write_trap(self.ctx.curr_fn_name, trap)
            self.logger.trap(trap + "\n")
