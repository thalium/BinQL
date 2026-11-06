#!/usr/bin/env python3
import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

console = Console()

_BINQL = "[binql] "


def _make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


# --- multi-binary support (--binaries) -------------------------------------
#
# One process, one Rich Progress, one worker thread per binary. Each worker
# spawns its own `codeql database create` and parses that child's [binql]
# lines, then reports progress through plain callbacks -- Progress.update /
# add_task are safe to call from several threads. No xargs, no per-user log
# aggregator, no interleaved TUIs fighting over the terminal.

PHASE_DESC = {
    "loading": "Loading",
    "batch_decompile": "Batch decompile",
    "func_reg": "Function register",
    "ctree": "C-tree extraction",
}
PHASE_ORDER = ["loading", "batch_decompile", "func_reg", "ctree"]
# Weight of each phase in a binary's 0..1 progress fraction. Batch decompile
# dominates wall time; loading is a sliver we can't measure inside.
PHASE_WEIGHT = {
    "loading": 0.02,
    "batch_decompile": 0.50,
    "func_reg": 0.24,
    "ctree": 0.24,
}


def _hexlic_products(path: Path) -> list[str]:
    today = date.today().isoformat()
    try:
        data = json.loads(path.read_text())
        return sorted(
            {
                addon["code"]
                for lic in data.get("payload", {}).get("licenses", [])
                if lic.get("end_date", "") >= today
                for addon in lic.get("add_ons", [])
                if addon.get("end_date", "") >= today and "code" in addon
            }
        )
    except Exception:
        return []


def _available_hexlics() -> list[tuple[Path, list[str]]]:
    d = Path.home() / ".idapro"
    out: list[tuple[Path, list[str]]] = []
    if d.exists():
        for p in sorted(d.glob("*.hexlic")):
            products = _hexlic_products(p)
            if products:
                out.append((p, products))
    return out


def resolve_binaries(patterns: list[str]) -> list[Path]:
    """Expand paths / globs to a deduped, ordered list of existing files."""
    seen: dict[Path, None] = {}
    for pat in patterns:
        p = Path(pat)
        if p.exists():
            matches = [p]
        elif any(ch in pat for ch in "*?["):
            if p.is_absolute():
                root = Path(p.anchor)
                matches = sorted(root.glob(str(p.relative_to(root))))
            else:
                matches = sorted(Path.cwd().glob(pat))
        else:
            matches = []
        if not matches:
            console.print(f"[bold red]No binary matches:[/bold red] {pat}")
            sys.exit(1)
        for m in matches:
            if m.is_file():
                seen[m.resolve()] = None
    if not seen:
        console.print("[bold red]--binaries matched no files[/bold red]")
        sys.exit(1)
    return list(seen)


def _await_exit(proc: subprocess.Popen) -> None:
    """Let the extractor exit on its own after a license mismatch.

    main.py closes the IDB and exits before auto-analysis; a signal would only
    be handled once auto-analysis returns, and a kill leaves unpacked IDB files.
    """
    try:
        proc.wait(timeout=60)
        return
    except subprocess.TimeoutExpired:
        proc.terminate()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _worker_env(
    repo_dir: Path,
    ida_root: Path,
    target: Path,
    extractor_log: Path,
    ida_log: Path,
    *,
    no_decompile: bool,
    log_level: str | None,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    env = {
        **os.environ,
        "BINQL_WORKSPACE_GIT": str(repo_dir),
        "BINQL_IDA_ROOT": str(ida_root),
        "BINQL_TARGET": str(target),
        "BINQL_EXTRACTOR_LOG": str(extractor_log),
        "BINQL_IDA_LOG": str(ida_log),
        "BINQL_NO_DECOMPILE": "1" if no_decompile else "0",
    }
    if log_level:
        env["BINQL_LOG_LEVEL"] = log_level
    if extra:
        env.update(extra)
    return env


def _worker_extract(
    *,
    ida_root: Path,
    target: Path,
    db_path: Path,
    repo_dir: Path,
    no_decompile: bool,
    log_level: str | None,
    auto: bool,
    emit_phase,
    emit_done,
    emit_note,
    register_pidfile,
    stop_evt: threading.Event,
) -> int:
    """Run `codeql database create` for one binary and return its exit code.

    Full output stays in ``db_path/log/extractor``; only phase updates and
    failures reach the shared progress view via the callbacks.
    """
    db_path.mkdir(parents=True, exist_ok=True)
    extractor_log = db_path / "log" / "extractor"
    ida_log = extractor_log / "ida"
    extractor_log.mkdir(parents=True, exist_ok=True)
    ida_log.touch()
    pidfile = extractor_log / "extractor.pid"
    register_pidfile(pidfile)

    cmd = [
        "codeql",
        "database",
        "create",
        "--language=binary",
        "--no-cleanup",
        "--overwrite",
        str(db_path),
    ]

    def _spawn(env: dict[str, str]) -> subprocess.Popen:
        return subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

    env = _worker_env(
        repo_dir,
        ida_root,
        target,
        extractor_log,
        ida_log,
        no_decompile=no_decompile,
        log_level=log_level,
    )
    retried = bool(os.environ.get("BINQL_AUTO_RETRY"))
    available = _available_hexlics() if auto else []
    current_products: list[str] = []

    total: int | None = None
    bd_total: int | None = None
    license_mismatch = False
    load_error: str | None = None
    raw_tail: list[str] = []

    proc = _spawn(env)
    relaunched = True
    # Restart the read loop on relaunch: the old process's stream is done.
    while relaunched:
        relaunched = False
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.rstrip()
            raw_tail.append(line)
            if len(raw_tail) > 60:
                raw_tail.pop(0)
            idx = line.find(_BINQL)
            if idx == -1:
                continue
            msg = line[idx + len(_BINQL) :]
            parts = msg.split()

            if msg.startswith("Loading "):
                emit_phase("loading", 0, None)
                emit_note(msg)
            elif msg.startswith("Loaded:"):
                total = int(parts[1])
                emit_done("loading")
                emit_note(msg)
            elif msg.startswith("license-file:"):
                p = Path(parts[1]) if len(parts) > 1 else None
                if p and p.exists():
                    current_products = _hexlic_products(p)
            elif msg.startswith("arch:"):
                arch_product = parts[2] if len(parts) > 2 else ""
                covered = bool(arch_product and arch_product in current_products)
                if auto and arch_product and not covered and not retried:
                    best = next(
                        (p for p, prods in available if arch_product in prods), None
                    )
                    if best is not None:
                        emit_note(f"license mismatch, retrying with {best.name}")
                        _await_exit(proc)
                        env = _worker_env(
                            repo_dir,
                            ida_root,
                            target,
                            extractor_log,
                            ida_log,
                            no_decompile=no_decompile,
                            log_level=log_level,
                            extra={"IDA_LICENSE": str(best), "BINQL_AUTO_RETRY": "1"},
                        )
                        retried = True
                        license_mismatch = False
                        total = bd_total = None
                        proc = _spawn(env)
                        relaunched = True
                        break
            elif msg.startswith("Batch decompile: skipped"):
                emit_note(msg)
            elif msg.startswith("Batch decompile:") and "/" in msg:
                bd_total = bd_total or int(parts[4])
                emit_phase("batch_decompile", int(parts[2]), bd_total)
            elif msg.startswith("Batch decompile:") and "/" not in msg:
                bd_total = int(parts[2])
                emit_phase("batch_decompile", 0, bd_total)
            elif msg.startswith("Batch decompile done"):
                emit_done("batch_decompile")
                emit_note(msg)
            elif msg.startswith("Function registration:") and "/" not in msg:
                total = total or int(parts[2])
                emit_phase("func_reg", 0, total)
            elif msg.startswith("C-tree extraction..."):
                emit_phase("ctree", 0, total)
            elif msg.startswith("Phase 1:"):
                total = total or int(parts[4])
                emit_phase("func_reg", int(parts[2]), total)
            elif msg.startswith("Function registration done"):
                emit_done("func_reg")
                emit_note(msg)
            elif msg.startswith("Phase 2:"):
                total = total or int(parts[4])
                emit_phase("ctree", int(parts[2]), total)
            elif msg.startswith("C-tree extraction done"):
                emit_done("ctree")
                emit_note(msg)
            elif msg.startswith(("Soft-stop requested", "Stopped early:")):
                emit_note(msg, warn=True)
            elif msg.startswith("license-hint"):
                license_mismatch = True
            elif msg.startswith("Load failed:"):
                load_error = msg.removeprefix("Load failed:").strip()
            # else: routine chatter -- left in the per-binary log only

    proc.wait()
    rc = proc.returncode
    if license_mismatch and rc == 0:
        rc = 1

    counts = {"ERROR": 0, "WARNING": 0}
    for level, fname in (("ERROR", "error"), ("WARNING", "warning")):
        lp = extractor_log / fname
        if lp.exists():
            counts[level] = sum(
                1
                for ln in lp.read_text(errors="replace").splitlines()
                if ln.startswith(f"{level} - ")
            )
    if load_error is not None:
        emit_note(
            f"FAILED: could not open binary: {load_error}  log: {extractor_log}",
            warn=True,
        )
    elif rc != 0:
        emit_note(
            f"FAILED (exit {rc})  errors={counts['ERROR']} "
            f"warnings={counts['WARNING']}  log: {extractor_log}",
            warn=True,
        )
        tail = "\n".join(ln for ln in raw_tail if _BINQL not in ln and ln.strip())[
            -1500:
        ]
        if tail:
            emit_note("codeql tail:\n" + tail, warn=True)
    elif counts["ERROR"] or counts["WARNING"]:
        emit_note(
            f"errors={counts['ERROR']} warnings={counts['WARNING']}  "
            f"log: {extractor_log}"
        )
    return rc


def run_many(
    ida_root: Path,
    targets: list[Path],
    workspace: Path,
    repo_dir: Path,
    *,
    jobs: int,
    verbose: bool = False,
    auto: bool = False,
    no_decompile: bool = False,
    log_level: str | None = None,
    database_root: Path | None = None,
) -> None:
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    dbroot = database_root or (workspace / "databases")

    # Disambiguate identical basenames (same .so from several APK versions):
    # tack on the first path component that actually differs between them.
    basenames = [t.name for t in targets]
    label: dict[Path, str] = {}
    for t in targets:
        if basenames.count(t.name) == 1:
            label[t] = t.name
            continue
        collisions = [x.parts for x in targets if x.name == t.name]
        s, minlen = 0, min(len(c) for c in collisions)
        while s < minlen - 1 and len({c[-(s + 1)] for c in collisions}) == 1:
            s += 1
        tp = t.parts
        disc = tp[-(s + 1)] if s + 1 <= len(tp) else tp[0]
        label[t] = f"{t.name} ({disc})"

    def _db_for(t: Path) -> Path:
        stem = label[t].replace(" ", "").replace("(", "-").replace(")", "")
        return dbroot / f"binql-{stem}-{ts}"

    G = 1000  # sub-integer granularity so partial binaries move the total bar
    lock = threading.Lock()
    frac: dict[str, float] = {label[t]: 0.0 for t in targets}
    results: dict[str, int] = {}
    completed_n = 0  # binaries that have actually returned (drives "N / M")
    pidfiles: list[Path] = []
    stop_evt = threading.Event()

    # Name and status are separate columns (not one concatenated description)
    # so Rich aligns them like a table instead of ragged per-row strings.
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        TextColumn("{task.fields[status]}"),
        BarColumn(bar_width=None),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )

    with progress:
        overall = progress.add_task("", total=len(targets) * G, status="")
        row = {
            label[t]: progress.add_task(label[t], total=G, status="[dim]queued[/dim]")
            for t in targets
        }

        def _refresh_overall() -> None:
            progress.update(
                overall,
                description=(
                    f"[bold]== TOTAL  {completed_n} / {len(targets)} ==[/bold]"
                ),
                completed=int(sum(frac.values()) * G),
            )

        _refresh_overall()

        def _register(pf: Path) -> None:
            with lock:
                pidfiles.append(pf)

        def _soft_stop_listener() -> None:
            while not stop_evt.is_set():
                line = sys.stdin.readline()
                if not line:
                    return
                if line.strip().lower() not in ("s", "stop"):
                    continue
                with lock:
                    pfs = list(pidfiles)
                n = 0
                for pf in pfs:
                    try:
                        os.kill(int(pf.read_text().strip()), signal.SIGUSR1)
                        n += 1
                    except (FileNotFoundError, ValueError, ProcessLookupError):
                        pass
                progress.print(
                    f"[yellow]Soft-stop sent to {n} running extractor(s); "
                    f"each finishes its current function, then saves.[/yellow]"
                )

        threading.Thread(target=_soft_stop_listener, daemon=True).start()
        progress.print(
            "[dim]Tip: type 's' + Enter to stop all running extractors safely "
            "(Ctrl+C does not).[/dim]"
        )

        def _make_emit(name: str):
            def emit_phase(phase: str, done: int, tot: int | None) -> None:
                w0 = sum(
                    PHASE_WEIGHT[p] for p in PHASE_ORDER[: PHASE_ORDER.index(phase)]
                )
                part = (done / tot) if tot else 0.0
                fr = min(1.0, w0 + part * PHASE_WEIGHT[phase])
                with lock:
                    if fr > frac[name]:
                        frac[name] = fr
                    progress.update(
                        row[name],
                        status=PHASE_DESC[phase],
                        completed=int(frac[name] * G),
                    )
                    _refresh_overall()

            def emit_done(phase: str) -> None:
                w1 = sum(
                    PHASE_WEIGHT[p] for p in PHASE_ORDER[: PHASE_ORDER.index(phase) + 1]
                )
                with lock:
                    if w1 > frac[name]:
                        frac[name] = w1
                    progress.update(row[name], completed=int(frac[name] * G))
                    _refresh_overall()

            def emit_note(msg: str, warn: bool = False) -> None:
                if not warn and not verbose:
                    return  # routine phase chatter -- per-binary log has it
                style = "yellow" if warn else "dim"
                progress.console.log(f"[{style}]{name}[/{style}]  {escape(msg)}")

            return emit_phase, emit_done, emit_note

        with ThreadPoolExecutor(max_workers=jobs) as ex:
            fut_name = {}
            for t in targets:
                name = label[t]
                ep, ed, en = _make_emit(name)
                fut = ex.submit(
                    _worker_extract,
                    ida_root=ida_root,
                    target=t,
                    db_path=_db_for(t),
                    repo_dir=repo_dir,
                    no_decompile=no_decompile,
                    log_level=log_level,
                    auto=auto,
                    emit_phase=ep,
                    emit_done=ed,
                    emit_note=en,
                    register_pidfile=_register,
                    stop_evt=stop_evt,
                )
                fut_name[fut] = name

            for fut in as_completed(fut_name):
                name = fut_name[fut]
                try:
                    rc = fut.result()
                except Exception as exc:
                    rc = 1
                    progress.console.log(
                        f"[red]{name}  crashed: {escape(str(exc))}[/red]"
                    )
                results[name] = rc
                with lock:
                    completed_n += 1
                    frac[name] = 1.0
                    tag = (
                        "[green]done[/green]"
                        if rc == 0
                        else f"[red]FAILED (exit {rc})[/red]"
                    )
                    progress.update(row[name], status=tag, completed=G)
                    _refresh_overall()

        stop_evt.set()

    ok = sorted(n for n, rc in results.items() if rc == 0)
    bad = sorted((n, rc) for n, rc in results.items() if rc != 0)
    tbl = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 2))
    tbl.add_column("Binary")
    tbl.add_column("Result")
    for n in ok:
        tbl.add_row(n, "[green]ok[/green]")
    for n, rc in bad:
        tbl.add_row(n, f"[red]exit {rc}[/red]")
    console.print(
        Panel(
            tbl,
            title=f"[bold]BinQL batch — {len(ok)} ok, {len(bad)} failed[/bold]",
            expand=False,
        )
    )
    console.print(f"  [dim]databases under:[/dim] {dbroot}")
    if bad:
        sys.exit(1)


def rich_choose(items: list[Path], header: str) -> Path:
    if not items:
        raise RuntimeError(f"No items to choose from ({header})")

    while True:
        table = Table(title=header, show_header=True)
        table.add_column("#", style="cyan", width=4)
        table.add_column("Name", style="green")

        for i, item in enumerate(items):
            table.add_row(str(i), item.name)

        console.print(table)
        choice = console.input("[bold yellow]Select number[/bold yellow] > ").strip()

        if not choice.isdigit():
            console.print("[red]Invalid input, enter a number[/red]")
            continue

        idx = int(choice)
        if 0 <= idx < len(items):
            return items[idx]

        console.print(f"[red]Out of range (0-{len(items) - 1})[/red]")


def resolve_ida(cli_arg: str | None) -> Path:
    if cli_arg:
        p = Path(cli_arg)
        if not p.exists():
            console.print(f"[bold red]IDA path does not exist:[/bold red] {p}")
            sys.exit(1)
        return p

    candidates = sorted(
        p for p in Path.home().iterdir() if p.is_dir() and "ida-pro" in p.name.lower()
    )
    if not candidates:
        console.print("[bold red]No IDA Pro installations found in $HOME[/bold red]")
        sys.exit(1)

    return rich_choose(candidates, "Select IDA Pro installation")


def resolve_binary(cli_arg: str | None, repo_dir: Path) -> Path:
    if cli_arg:
        p = Path(cli_arg)
        if not p.exists():
            console.print(f"[bold red]Binary path does not exist:[/bold red] {p}")
            sys.exit(1)
        return p

    targets = sorted(
        p for p in (repo_dir / "targets").rglob("*.i64") if "editable" not in p.name
    )
    if not targets:
        console.print("[bold red]No .i64 targets found in targets/[/bold red]")
        sys.exit(1)

    return rich_choose(targets, "Select target IDB")


def run(
    ida_root: Path,
    target: Path,
    workspace: Path,
    repo_dir: Path,
    verbose: bool = False,
    auto: bool = False,
    database: Path | None = None,
    no_decompile: bool = False,
    log_level: str | None = None,
    mark: bool = False,
) -> None:
    if database is not None:
        db_path = database
    else:
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        db_path = workspace / "databases" / f"binql-{target.name}-{timestamp}"
    db_path.mkdir(parents=True, exist_ok=True)

    extractor_log = db_path / "log" / "extractor"
    ida_log = extractor_log / "ida"
    extractor_log.mkdir(parents=True, exist_ok=True)
    ida_log.touch()
    # Written by autobuild.sh once the extractor process is up; used to send
    # it a targeted soft-stop (SIGUSR1) instead of a raw Ctrl+C, which would
    # hit the whole codeql/autobuild/extractor process tree at once and can
    # corrupt the IDB if it lands mid-write.
    pidfile = extractor_log / "extractor.pid"

    env = {
        **os.environ,
        "BINQL_WORKSPACE_GIT": str(repo_dir),
        "BINQL_IDA_ROOT": str(ida_root),
        "BINQL_TARGET": str(target),
        "BINQL_EXTRACTOR_LOG": str(extractor_log),
        "BINQL_IDA_LOG": str(ida_log),
        "BINQL_NO_DECOMPILE": "1" if no_decompile else "0",
    }
    if log_level:
        env["BINQL_LOG_LEVEL"] = log_level

    if mark:
        # Tag the IDB as already batch-decompiled and exit -- no CodeQL DB.
        env["BINQL_MARK_DECOMPILED"] = "1"
        main_py = repo_dir / "src" / "main.py"
        console.print(
            f"[bold]Marking[/bold] {target.name} as batch-decompiled "
            f"(writes the IDB marker, no extraction)"
        )
        rc = subprocess.run(["uv", "run", str(main_py)], env=env).returncode
        sys.exit(rc)

    cmd = [
        "codeql",
        "database",
        "create",
        "--language=binary",
        "--no-cleanup",
        "--overwrite",
        str(db_path),
    ]

    summary = Table(show_header=False, box=None, padding=(0, 1))
    summary.add_column(style="cyan")
    summary.add_column(style="white")
    summary.add_row("IDA", str(ida_root))
    summary.add_row("Target", str(target))
    summary.add_row("Database", str(db_path))
    summary.add_row("Command", " ".join(cmd))
    console.print(Panel(summary, title="[bold]BinQL run[/bold]", expand=False))
    console.print(
        "[dim]Tip: type 's' + Enter any time to stop safely — finishes the "
        "current function, then saves the IDB. Ctrl+C does not do this.[/dim]"
    )

    import json as _json
    from datetime import date as _date

    from rich.console import Group

    def _hexlic_products(path: Path) -> list[str]:
        today = _date.today().isoformat()
        try:
            data = _json.loads(path.read_text())
            return sorted(
                {
                    addon["code"]
                    for lic in data.get("payload", {}).get("licenses", [])
                    if lic.get("end_date", "") >= today
                    for addon in lic.get("add_ons", [])
                    if addon.get("end_date", "") >= today and "code" in addon
                }
            )
        except Exception:
            return []

    idapro_dir = Path.home() / ".idapro"
    base_cmd = f"uv run {os.path.relpath(__file__)} --ida {ida_root} --binary {target}"
    current_lic_path: Path | None = None
    current_products: list[str] = []
    available: list[tuple[Path, list[str]]] = []
    if idapro_dir.exists():
        for p in sorted(idapro_dir.glob("*.hexlic")):
            products = _hexlic_products(p)
            if products:
                available.append((p, products))

    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None

    total: int | None = None
    task0_id = task1_id = task2_id = load_task_id = None
    bd_total: int | None = None
    arch_proc: str | None = None
    arch_product: str | None = None
    license_mismatch: bool = False
    load_error: str | None = None
    stopped_early: bool = False
    best_cmd: str | None = None

    def _build_license_table(
        arch_prod: str | None,
    ) -> tuple[Table, str | None, Path | None]:
        tbl = Table(
            show_header=True, header_style="bold cyan", box=None, padding=(0, 1)
        )
        tbl.add_column("License file")
        tbl.add_column("Decompilers")
        if current_lic_path:
            marker = (
                " [green]✓[/green]"
                if arch_prod and arch_prod in current_products
                else ""
            )
            tbl.add_row(
                f"[cyan]▶[/cyan] {current_lic_path.name}{marker}",
                ", ".join(current_products) or "[dim]none[/dim]",
            )
            tbl.add_section()
        best: str | None = None
        best_path: Path | None = None
        for p, products in available:
            if current_lic_path and p == current_lic_path:
                continue
            has = bool(arch_prod and arch_prod in products)
            marker = " [green]✓[/green]" if has else ""
            tbl.add_row(p.name + marker, ", ".join(products))
            if has and best is None:
                best = f"IDA_LICENSE={p} {base_cmd}"
                best_path = p
        return tbl, best, best_path

    raw_lines: list[str] = []
    pending_relaunch: Path | None = None

    with _make_progress() as progress:

        def _soft_stop_listener() -> None:
            while True:
                line = sys.stdin.readline()
                if not line:
                    return  # stdin closed
                if line.strip().lower() not in ("s", "stop"):
                    continue
                try:
                    pid = int(pidfile.read_text().strip())
                except (FileNotFoundError, ValueError):
                    progress.print(
                        "[yellow]Soft-stop: extractor not ready yet, try again shortly.[/yellow]"
                    )
                    continue
                try:
                    os.kill(pid, signal.SIGUSR1)
                except ProcessLookupError:
                    progress.print("[yellow]Soft-stop: process already gone.[/yellow]")

        threading.Thread(target=_soft_stop_listener, daemon=True).start()

        for raw in proc.stdout:
            line = raw.rstrip()
            raw_lines.append(line)
            idx = line.find(_BINQL)
            if idx == -1:
                continue
            msg = line[idx + len(_BINQL) :]
            parts = msg.split()

            def print_msg(msg: str = msg) -> None:
                progress.print(
                    f"[bold cyan]▶[/bold cyan] [bright_green]{escape(msg)}[/bright_green]",
                    highlight=False,
                )

            if msg.startswith("Loading "):
                print_msg()
                # IDA's auto-analysis runs here with no [binql] output at all —
                # can take minutes on a large binary. Indeterminate (pulsing)
                # bar so this doesn't read as a hang.
                load_task_id = progress.add_task(
                    "Waiting for IDA auto-analysis (no output until done, "
                    "can take minutes on large binaries)",
                    total=None,
                )

            elif msg.startswith("Loaded:"):
                if load_task_id is not None:
                    progress.remove_task(load_task_id)
                    load_task_id = None
                total = int(parts[1])
                print_msg()

            elif msg.startswith("license-file:"):
                p = Path(parts[1]) if len(parts) > 1 else None
                if p and p.exists():
                    current_lic_path = p
                    current_products = _hexlic_products(p)

            elif msg.startswith("arch:"):
                arch_proc = parts[1] if len(parts) > 1 else ""
                arch_product = parts[2] if len(parts) > 2 else ""
                tbl, best_cmd, best_path = _build_license_table(arch_product)
                covered = bool(arch_product and arch_product in current_products)
                if (
                    auto
                    and arch_product
                    and not covered
                    and best_path
                    and not os.environ.get("BINQL_AUTO_RETRY")
                ):
                    pending_relaunch = best_path
                    break
                if verbose:
                    arch_line = f"[bold]Architecture:[/bold] {arch_proc}" + (
                        f" (requires [yellow]{arch_product}[/yellow])"
                        if arch_product
                        else ""
                    )
                    legend = "[dim]▶ active license   ✓ covers required arch[/dim]"
                    progress.print(
                        Panel(
                            Group(arch_line, "", tbl, legend),
                            title="Licenses",
                            expand=False,
                        )
                    )

            elif msg.startswith("Batch decompile:") and "/" in msg:
                done = int(parts[2])
                if task0_id is None:
                    bd_total = bd_total or int(parts[4])
                    task0_id = progress.add_task("Batch decompile", total=bd_total)
                progress.update(task0_id, completed=done)

            elif msg.startswith("Batch decompile: skipped"):
                print_msg()

            elif msg.startswith("Batch decompile:") and "/" not in msg:
                bd_total = int(parts[2])
                if task0_id is None:
                    task0_id = progress.add_task("Batch decompile", total=bd_total)

            elif msg.startswith("Batch decompile done"):
                if task0_id is not None:
                    progress.update(task0_id, completed=bd_total or 0)
                print_msg()

            elif msg.startswith("Function registration:") and "/" not in msg:
                total = total or int(parts[2])
                if task1_id is None:
                    task1_id = progress.add_task("Function registration", total=total)

            elif msg.startswith("C-tree extraction..."):
                if task2_id is None:
                    task2_id = progress.add_task("C-tree extraction", total=total)

            elif msg.startswith("Phase 1:"):
                done = int(parts[2])
                if task1_id is None:
                    task1_id = progress.add_task(
                        "Function registration", total=total or int(parts[4])
                    )
                progress.update(task1_id, completed=done)

            elif msg.startswith("Function registration done"):
                if task1_id is not None:
                    progress.update(task1_id, completed=total or 0)
                print_msg()

            elif msg.startswith("Phase 2:"):
                done = int(parts[2])
                if task2_id is None:
                    task2_id = progress.add_task(
                        "C-tree extraction", total=total or int(parts[4])
                    )
                progress.update(task2_id, completed=done)

            elif msg.startswith("C-tree extraction done"):
                if task2_id is not None:
                    progress.update(task2_id, completed=total or 0)
                print_msg()

            elif msg.startswith("Soft-stop requested"):
                progress.print(
                    f"[bold yellow]■[/bold yellow] [yellow]{escape(msg)}[/yellow]",
                    highlight=False,
                )

            elif msg.startswith("Stopped early:"):
                stopped_early = True
                progress.print(
                    f"[bold yellow]■[/bold yellow] [yellow]{escape(msg)}[/yellow]",
                    highlight=False,
                )

            elif msg.startswith("license-hint"):
                license_mismatch = True

            elif msg.startswith("Load failed:"):
                load_error = msg.removeprefix("Load failed:").strip()

            else:
                print_msg()

    if pending_relaunch is not None:
        _await_exit(proc)
    proc.wait()

    if load_error is not None:
        console.print(
            Panel(
                f"[bold]Target:[/bold] {escape(str(target))}\n"
                f"[bold]Reason:[/bold] [yellow]{escape(load_error)}[/yellow]\n"
                f"[dim]IDA log:[/dim] {extractor_log / 'ida.log'}",
                title="[bold red]ERROR: IDA could not open the binary[/bold red]",
                expand=False,
            )
        )
        sys.exit(1)

    if pending_relaunch is not None:
        console.print(
            f"[bold cyan]▶[/bold cyan] [yellow]License mismatch, retrying with "
            f"{pending_relaunch.name}...[/yellow]"
        )
        retry_env = {
            **os.environ,
            "IDA_LICENSE": str(pending_relaunch),
            "BINQL_AUTO_RETRY": "1",
        }
        argv = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--ida",
            str(ida_root),
            "--binary",
            str(target),
            # Reuse the same database dir: the relaunch must not auto-name a
            # second one (and it would anyway land relative to cwd here).
            "--database",
            str(db_path),
        ]
        if verbose:
            argv.append("-v")
        if auto:
            argv.append("--auto")
        if no_decompile:
            argv.append("--no-decompile")
        if log_level:
            argv += ["--log-level", log_level]
        os.execve(sys.executable, argv, retry_env)

    if license_mismatch:
        console.print(
            Panel(
                f"[bold]Rerun:[/bold] [bold yellow]{escape(best_cmd or f'IDA_LICENSE=<path> {base_cmd}')}[/bold yellow]",
                title="[bold red]ERROR: License mismatch[/bold red]",
                expand=False,
            )
        )

    # Per-level files written by TrapLogger: one record per line prefixed
    # "<LEVEL> - "; count those, not every physical line (a multi-line message
    # or a string-literal TRAP tuple must not inflate the tally).
    counts: dict[str, int] = {"ERROR": 0, "WARNING": 0}
    flagged: dict[str, list[str]] = {"ERROR": [], "WARNING": []}
    for level, fname in (("ERROR", "error"), ("WARNING", "warning")):
        p = extractor_log / fname
        if not p.exists():
            continue
        for line in p.read_text(errors="replace").splitlines():
            if line.startswith(f"{level} - "):
                counts[level] += 1
                flagged[level].append(line)
    show_log = verbose or proc.returncode != 0 or license_mismatch
    if any(counts.values()) and show_log:
        log_summary = Table(show_header=False, box=None, padding=(0, 2))
        log_summary.add_column(style="bold")
        log_summary.add_column(justify="right")
        for level, n in counts.items():
            style = "red" if level == "ERROR" else "orange1"
            log_summary.add_row(f"[{style}]{level}[/{style}]", str(n))
        console.print(Panel(log_summary, title="Extractor log", expand=False))
        for line in flagged["ERROR"]:
            console.print(f"  [red]{escape(line)}[/red]", highlight=False)
        for line in flagged["WARNING"]:
            console.print(f"  [orange1]{escape(line)}[/orange1]", highlight=False)

    if license_mismatch:
        console.print(f"  [dim]Extractor log:[/dim] {extractor_log}")
        sys.exit(1)

    if stopped_early:
        console.print(
            f"[bold yellow]Stopped early.[/bold yellow] IDB saved, "
            f"but the CodeQL database is incomplete: {db_path}"
        )
    elif proc.returncode == 0:
        console.print(f"[bold green]Done.[/bold green] Database: {db_path}")
    else:
        non_binql = [ln for ln in raw_lines if _BINQL not in ln and ln.strip()]
        if non_binql:
            tail = non_binql[-40:]
            console.print(
                Panel(
                    "\n".join(escape(ln) for ln in tail),
                    title="[bold red]CodeQL output[/bold red]",
                    expand=False,
                )
            )
        console.print(f"[bold red]Failed (exit {proc.returncode})[/bold red]")
        console.print(f"  [dim]Extractor log:[/dim] {extractor_log}")
        sys.exit(proc.returncode)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run BinQL extractor.",
    )
    parser.add_argument("--ida", metavar="PATH", help="Path to IDA Pro installation")
    parser.add_argument("--binary", metavar="PATH", help="Path to target .i64 file")
    parser.add_argument(
        "--binaries",
        nargs="+",
        metavar="GLOB",
        help="Two or more binaries (paths or globs) to extract in parallel "
        "under one combined progress view. A single match falls back to "
        "the plain --binary behaviour.",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        metavar="N",
        help="Parallel workers for --binaries (default: CPU count)",
    )
    parser.add_argument(
        "--database",
        metavar="PATH",
        help="Exact database directory to use, overrides auto-naming",
    )
    parser.add_argument(
        "--database-root",
        metavar="DIR",
        help="Parent directory for auto-named databases in --binaries mode "
        "(default: ./databases)",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Interactively select IDA / binary if not provided",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show licenses table and extractor log",
    )
    parser.add_argument(
        "-a",
        "--auto",
        action="store_true",
        help="On license mismatch, auto-relaunch with a matching IDA_LICENSE",
    )
    parser.add_argument(
        "--no-decompile",
        action="store_true",
        help="Skip the batch decompile pass; trust the IDB's existing analysis",
    )
    parser.add_argument(
        "--mark",
        action="store_true",
        help="Tag the IDB as already batch-decompiled (write the marker) and "
        "exit; later runs then skip the pass. No database is produced.",
    )
    parser.add_argument(
        "--log-level",
        metavar="LEVEL",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Extractor log level (default: INFO)",
    )
    parser.add_argument(
        "--debug",
        dest="log_level",
        action="store_const",
        const="DEBUG",
        help="Shorthand for --log-level DEBUG",
    )
    args = parser.parse_args()

    have_target = args.binary or args.binaries or args.interactive
    if not args.ida or not have_target:
        parser.print_help()
        sys.exit(0)
    if args.binaries and args.binary:
        parser.error("use either --binary or --binaries, not both")
    if args.binaries and args.mark:
        parser.error("--mark is single-target only; use --binary")
    if args.binaries and args.database:
        parser.error("--database is single-target; use --database-root with --binaries")

    # repo_dir: committed assets (targets/, coverage root). workspace: where
    # run outputs go (databases/) -- the launch dir, not the script's dir.
    repo_dir = Path(__file__).resolve().parent
    workspace = Path.cwd()

    try:
        ida_root = resolve_ida(args.ida)

        if args.binaries:
            targets = resolve_binaries(args.binaries)
            if len(targets) == 1:
                run(
                    ida_root,
                    targets[0],
                    workspace,
                    repo_dir,
                    verbose=args.verbose,
                    auto=args.auto,
                    database=None,
                    no_decompile=args.no_decompile,
                    log_level=args.log_level,
                    mark=args.mark,
                )
            else:
                run_many(
                    ida_root,
                    targets,
                    workspace,
                    repo_dir,
                    jobs=args.jobs or os.cpu_count() or 4,
                    verbose=args.verbose,
                    auto=args.auto,
                    no_decompile=args.no_decompile,
                    log_level=args.log_level,
                    database_root=(
                        Path(args.database_root) if args.database_root else None
                    ),
                )
            return

        target = resolve_binary(args.binary, repo_dir)
        database = Path(args.database) if args.database else None
        run(
            ida_root,
            target,
            workspace,
            repo_dir,
            verbose=args.verbose,
            auto=args.auto,
            database=database,
            no_decompile=args.no_decompile,
            log_level=args.log_level,
            mark=args.mark,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
