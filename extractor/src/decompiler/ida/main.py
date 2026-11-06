import idapro

import json
import os
import shutil
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_netnode
import ida_registry
import idaapi
import idc

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

from decompiler.ida.analysis import Analyse, _check_hexrays_license, _required_product
from decompiler.ida.types import TypesManager
from decompiler.ida.utils import Context
from utils.logger import TrapLogger

logger = TrapLogger.from_env()

# Soft-stop: set by SIGUSR1 (run.py's "type s + Enter"), checked between
# functions in every extraction loop so we always break at a safe point —
# never mid-decompile / mid-write — then save the IDB before exiting.
_stop_event = threading.Event()


# Persistent "the full batch decompile pass already ran on this IDB" marker.
# Stored in a private netnode, persisted by save_database() at the end of a
# run, so a later extraction of the same IDB can skip the pass. Fingerprint =
# input file MD5 + function count, so it invalidates if the binary changed or
# IDA re-analysed and found more functions.
_BATCH_NN = "$ binql.extract"
_BATCH_FP_KEY = "batch_fp"


def _batch_fingerprint() -> str:
    md5 = ida_nalt.retrieve_input_file_md5() or b""
    return f"{md5.hex()}:{ida_funcs.get_func_qty()}"


def _batch_already_done() -> bool:
    # A marker read/write must never abort extraction: on any netnode trouble,
    # fall back to "not done" so the batch pass simply runs again.
    try:
        raw = ida_netnode.netnode(_BATCH_NN, 0, False).hashstr_buf(_BATCH_FP_KEY)
        return bool(raw) and raw.decode(errors="replace") == _batch_fingerprint()
    except Exception as exc:
        logger.debug(f"batch marker read failed: {exc!r}")
        return False


def _mark_batch_done() -> None:
    try:
        # Create-or-open by name (BADNODE constructor + create() silently
        # no-ops when the node already exists, then hashset_buf crashes).
        nn = ida_netnode.netnode(_BATCH_NN, 0, True)
        nn.hashset_buf(_BATCH_FP_KEY, _batch_fingerprint().encode())
    except Exception as exc:
        logger.debug(f"batch marker write failed: {exc!r}")


def _finish_auto_analysis() -> None:
    # auto_wait() returns early when analysis was disabled in the IDB or
    # cancelled; loop until the queue is really empty, else functions go missing
    # and the saved IDB resumes analysis on next open.
    ida_auto.enable_auto(True)
    for _ in range(10):
        if ida_auto.auto_wait() and ida_auto.auto_is_ok():
            return
    logger.warning("auto-analysis queue still not empty after 10 auto_wait() rounds")
    _status("Warning: IDA auto-analysis did not finish")


def _save_idb() -> None:
    # A soft-stop wants out fast; IDA resumes any leftover queue on next open.
    if not _stop_event.is_set():
        _finish_auto_analysis()
    # Close, not just save: an IDB left open keeps its unpacked .id0/.nam/...
    # files on disk, and the next open reuses them instead of re-analysing.
    _close_idb(save=True)


_db_open = False


def _close_idb(save: bool) -> None:
    global _db_open
    if _db_open:
        _db_open = False
        idapro.close_database(save=save)


def _on_terminate(signum, frame) -> None:
    # The in-memory analysis was never flushed: drop the unpacked files rather
    # than leave a partial database the next run would silently reuse.
    _close_idb(save=False)
    os._exit(128 + signum)


def _status(msg: str) -> None:
    print(f"[binql] {msg}", flush=True)  # noqa: T201


def _on_soft_stop(signum, frame) -> None:
    if not _stop_event.is_set():
        _status("Soft-stop requested, finishing current function then saving...")
    _stop_event.set()


def _write_database_info(
    target: str, extracted_at: datetime, sha256: str | None = None
) -> None:
    """Write `binql.yml` at the database root: which BinQL, commit and IDA built it, from what.

    The BinQL version and commit come from `binql-build.json`, written next to the
    installed extractor by `manage.py install`. `sha256` is the input binary's, as IDA
    recorded it: known only once the database is open, so this runs again then.
    """
    build = {}
    build_file = Path(__file__).resolve().parents[3] / "binql-build.json"
    try:
        build = json.loads(build_file.read_text())
    except (OSError, ValueError) as exc:
        logger.warning(f"{build_file} unreadable, BinQL version unknown: {exc!r}")

    commit = build.get("commit") or "unknown"
    if build.get("dirty"):
        commit += " (with uncommitted changes)"
    lines = [
        "# Database extracted by BinQL (https://github.com/thalium/binql)",
        f"binql_version: {build.get('version') or 'unknown'}",
        f"binql_commit: {commit}",
        f"ida_version: {idaapi.get_kernel_version()}",
        f"target: {os.path.basename(target)}"
        + (f" (SHA256: {sha256})" if sha256 else ""),
        f"extracted_at: {extracted_at.isoformat(timespec='seconds')}",
    ]
    wip_db = os.environ.get("CODEQL_EXTRACTOR_BINARY_WIP_DATABASE")
    if not wip_db:
        logger.debug("CODEQL_EXTRACTOR_BINARY_WIP_DATABASE is not set, no binql.yml")
        return
    try:
        Path(wip_db, "binql.yml").write_text("\n".join(lines) + "\n")
    except OSError as exc:
        logger.warning(f"binql.yml not written: {exc!r}")


def _store_idb() -> None:
    """Save and close the IDB, then keep a copy in the database's `idb/` directory.

    Closing packs the IDB into a single, complete `.i64`; copying it while open
    could miss the unpacked `.id0`/`.id1`/... state.
    """
    if not _stop_event.is_set():
        _finish_auto_analysis()
    idb = idc.get_idb_path()
    _close_idb(save=True)
    wip_db = os.environ.get("CODEQL_EXTRACTOR_BINARY_WIP_DATABASE")
    if not wip_db:
        return
    idb_dir = Path(wip_db, "idb")
    copy = idb_dir / Path(idb).name
    if Path(idb).resolve() == copy.resolve():
        return  # Read-only target: IDA already worked on the copy in idb/.
    try:
        idb_dir.mkdir(exist_ok=True)
        shutil.copy2(idb, copy)
        _status(f"IDB saved in the database: idb/{copy.name}")
    except OSError as exc:
        logger.warning(f"IDB not copied into the database: {exc!r}")


def _writable_target(target: str) -> str:
    """Return a path IDA can open in place.

    IDA writes the .i64 (and its unpacked .id0/.id1/... files) next to the
    input, so a binary in a read-only directory like /usr/bin fails to open.
    In that case work on a copy inside the CodeQL database instead.
    """
    target_dir = os.path.dirname(os.path.abspath(target))
    if os.access(target_dir, os.W_OK):
        return target
    wip_db = os.environ.get("CODEQL_EXTRACTOR_BINARY_WIP_DATABASE", "/tmp")
    idb_dir = os.path.join(wip_db, "idb")
    os.makedirs(idb_dir, exist_ok=True)
    copy = os.path.join(idb_dir, os.path.basename(target))
    shutil.copy2(target, copy)
    _status(f"{target_dir} is not writable, working on a copy: {copy}")
    return copy


def _open_failure_reason(target: str) -> str:
    """Best-effort explanation for a failed idapro.open_database().

    idalib only returns an undocumented error code, so check the usual
    culprits ourselves.
    """
    if not os.path.exists(target):
        return f"{target} does not exist"
    if not os.path.isfile(target):
        return f"{target} is not a regular file"
    if not os.access(target, os.R_OK):
        return f"{target} is not readable"
    target_dir = os.path.dirname(os.path.abspath(target))
    if not os.access(target_dir, os.W_OK):
        return f"{target_dir} is not writable (IDA creates its database there)"
    base = os.path.splitext(target)[0] if target.endswith((".i64", ".idb")) else target
    leftovers = [
        os.path.basename(base + ext)
        for ext in (".id0", ".id1", ".id2", ".nam", ".til")
        if os.path.exists(base + ext)
    ]
    if leftovers:
        return (
            f"unpacked database files left next to the target ({', '.join(leftovers)}): "
            "another IDA instance has it open, or a previous run crashed; "
            "close it or delete them"
        )
    for idb in (base + ".i64", base + ".idb"):
        if os.path.exists(idb) and not os.access(idb, os.R_OK | os.W_OK):
            return f"existing database {idb} is not readable/writable"
    return "IDA could not load the file (unsupported format or corrupted database?)"


def visitor_main():
    global _db_open
    signal.signal(signal.SIGUSR1, _on_soft_stop)
    signal.signal(signal.SIGTERM, _on_terminate)

    target = os.environ.get("BINQL_TARGET", "")
    if not target:
        logger.debug("BINQL_TARGET is not set.")

    extracted_at = datetime.now(timezone.utc)
    _write_database_info(target, extracted_at)

    _status(f"Loading {os.path.basename(target)}...")
    t0 = time.monotonic()
    opened = _writable_target(target)
    # Open without analysis so the arch (and a license mismatch) is reported
    # within seconds, not after a full auto-analysis of a large binary.
    rc = idapro.open_database(opened, run_auto_analysis=False)
    if rc != 0:
        reason = _open_failure_reason(opened)
        logger.error(f"IDA failed to open {opened} (open_database={rc}): {reason}")
        _status(f"Load failed: {reason} (open_database={rc})")
        sys.exit(1)
    _db_open = True

    proc = idc.get_inf_attr(idc.INF_PROCNAME)
    required = _required_product(proc)
    ida_lic_env = os.environ.get("IDA_LICENSE", "")
    lic_path = ida_lic_env.removeprefix("keyfile=")
    if not lic_path:
        lic_path = ida_registry.reg_read_string("license_file_path") or ""
    if lic_path:
        _status(f"license-file: {lic_path}")
    _status(f"arch: {proc} {required or ''}")

    # Fail before auto-analysis when the given license lacks this arch's
    # decompiler, so run.py can relaunch with the right one right away.
    if lic_path:
        err, _ = _check_hexrays_license(proc, lic_path)
        if err:
            logger.error(err)
            _status("license-hint")
            _close_idb(save=False)
            sys.exit(3)

    _finish_auto_analysis()

    input_sha256 = ida_nalt.retrieve_input_file_sha256()
    _write_database_info(
        target, extracted_at, input_sha256.hex() if input_sha256 else None
    )

    num_functions = ida_funcs.get_func_qty()
    _status(f"Loaded: {num_functions} functions ({time.monotonic() - t0:.1f}s)")

    if os.environ.get("BINQL_MARK_DECOMPILED") == "1":
        # run.py --mark: tag this IDB as already fully batch-decompiled so
        # later runs skip the pass via the completion marker. No extraction.
        _mark_batch_done()
        _save_idb()
        _status("Marked as batch-decompiled; skipping extraction.")
        return

    _MERR_LICENSE = -23
    _MERR_ONLY32 = -24
    _MERR_ONLY64 = -25
    _MERR_LABELS = {
        _MERR_LICENSE: "no valid Hex-Rays license",
        _MERR_ONLY32: "32-bit decompiler unavailable (need HEXX86)",
        _MERR_ONLY64: "64-bit decompiler unavailable (need HEXX64)",
    }

    if not ida_hexrays.init_hexrays_plugin():
        err, _ = _check_hexrays_license(proc)
        logger.error(err or f"Hex-Rays decompiler unavailable for arch '{proc}'")
        _status("license-hint")
        _save_idb()
        return

    import idautils as _idautils

    hf = ida_hexrays.hexrays_failure_t()
    for _ea in _idautils.Functions():
        _cfunc = ida_hexrays.decompile(_ea, hf)
        if _cfunc:
            break
        if hf.code in _MERR_LABELS:
            logger.error(
                f"Hex-Rays license error for arch '{proc}': {_MERR_LABELS[hf.code]}"
            )
            _status("license-hint")
            _save_idb()
            return
        break

    # Force a full decompile pass — the equivalent of Ctrl+F5 in the GUI — so
    # every function's pseudocode / microcode is generated and cached before
    # per-function extraction, and cross-function type propagation has run once
    # globally. Reported in the same "N / total" cadence as the phases below so
    # run.py can draw a bar.
    #
    # Skipped only when explicitly told (--no-decompile) or when this IDB
    # already carries the completion marker from a previous full pass. A plain
    # .idb/.i64 is NOT trusted to be decompiled: a bare `idat -B` IDB has no
    # Hex-Rays type propagation, and skipping the pass there degrades the
    # extraction.
    if os.environ.get("BINQL_NO_DECOMPILE") == "1":
        _status("Batch decompile: skipped (--no-decompile)")
    elif _batch_already_done():
        _status("Batch decompile: skipped (already done for this IDB)")
    else:
        # Decompiling queues new analysis work (call targets, type propagation)
        # that can create functions: drain it and decompile the newcomers until
        # the function set is stable.
        done: set[int] = set()
        eas = list(_idautils.Functions())
        n_bd = len(eas)
        _status(f"Batch decompile: {n_bd} functions...")
        t0 = time.monotonic()
        t_last = t0
        while eas and not _stop_event.is_set():
            for ea in eas:
                if _stop_event.is_set():
                    _status(f"Batch decompile stopped early: {len(done)} / {n_bd}")
                    break
                ida_hexrays.decompile(ea, hf)
                done.add(ea)
                now = time.monotonic()
                if now - t_last >= 2.0:  # seconds between progress reports
                    _status(f"Batch decompile: {len(done)} / {n_bd}")
                    t_last = now
            else:
                _finish_auto_analysis()
                eas = [ea for ea in _idautils.Functions() if ea not in done]
                n_bd += len(eas)
        if not _stop_event.is_set():
            _mark_batch_done()
            _status(f"Batch decompile done ({time.monotonic() - t0:.1f}s)")

    if _stop_event.is_set():
        _store_idb()
        _status("Stopped early: IDB saved, extraction incomplete.")
        return

    logger.info("-------- VISITOR START  --------")

    ctx = Context(
        0,
        "",
        ida_hexrays.cfunc_t,
        dict[str | int, int](),
        dict[int, int](),
        list[str](),
        set[str](),
        dict[str, int](),
        dict[str, int](),
        TypesManager | None,
    )

    analysis = Analyse(ctx, report=_status, should_stop=_stop_event.is_set)

    _status(f"Function registration: {num_functions} functions...")
    t0 = time.monotonic()
    analysis.analyse_binary()
    if analysis.license_product_hint:
        _status("license-hint")
        _save_idb()
        return
    if not analysis.stopped_early:
        _status(f"Function registration done ({time.monotonic() - t0:.1f}s)")

        _status("C-tree extraction...")
        t0 = time.monotonic()
        analysis.analyse_function()
        if not analysis.stopped_early:
            _status(f"C-tree extraction done ({time.monotonic() - t0:.1f}s)")

    logger.info("-------- VISITOR END  --------")

    _store_idb()
    if analysis.stopped_early:
        _status("Stopped early: IDB saved, extraction incomplete.")
    else:
        _status("Extraction complete.")
