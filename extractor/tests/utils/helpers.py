import csv
import fcntl
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

# --- IDA ---


def version_key(path: Path):
    """Extract version numbers for sorting (e.g., ida_pro_9.1 -> [9,1])."""
    match = re.search(r"(\d+)\.(\d+)", path.name)
    if match:
        return [int(match.group(1)), int(match.group(2))]
    return [0, 0]


def ida_at_least(ida_version: str, minimum: str) -> bool:
    """Compare major.minor of `ida_version` (e.g. "9.5-beta-2") against `minimum`."""

    def key(v: str) -> tuple[int, int]:
        major, minor = v.split("-", 1)[0].split(".")[:2]
        return int(major), int(minor)

    return key(ida_version) >= key(minimum)


def find_ida_root(home: Path, version: str | None = None):
    """Find IDA Pro directories; with `version`, prefer `<home>/ida-pro-<version>`, else its highest `-beta-<n>`."""
    if version:
        release = home / f"ida-pro-{version}"
        if release.is_dir():
            return release
        betas = [
            d
            for d in home.glob(f"ida-pro-{version}-beta-*")
            if d.is_dir() and d.name.rsplit("-", 1)[1].isdigit()
        ]
        if not betas:
            raise RuntimeError(
                f"No IDA Pro directory found for {version} under {home}."
            )
        return max(betas, key=lambda d: int(d.name.rsplit("-", 1)[1]))
    ida_dirs = [d for d in home.iterdir() if "ida" in d.name and "pro" in d.name]
    ida_dirs = sorted(ida_dirs, key=version_key, reverse=True)
    if not ida_dirs:
        raise RuntimeError(f"No IDA Pro directory found matching version {version}.")
    return ida_dirs[0]


# --- Utils ---


def get_src_dir(test_file: Path) -> Path:
    src = test_file.parent / "src"
    if not src.is_dir():
        raise FileNotFoundError(f"Expected src directory not found: {src}")
    return src


def cleanup_folder(folder: Path):
    for item in folder.iterdir():
        if item.is_file():
            item.unlink()
        elif item.is_dir():
            shutil.rmtree(item)


def load_csv_matrix(path: Path):
    matrix = []
    with open(path) as f:
        reader = csv.reader(f)
        for row in reader:
            matrix.append([c.strip() for c in row])
    return matrix


def sanitize_nodeid(nodeid: str) -> str:
    """Pytest nodeid -> filesystem-safe dir name (`a.py::t[x]` -> `a.py__t_x`)."""
    return (
        nodeid.replace("::", "__").replace("/", "_").replace("[", "_").replace("]", "")
    )


# --- Cleanup ---


def cleanup(_cwd: Path, target: str) -> None:
    shutil.rmtree(_cwd / "db", ignore_errors=True)
    shutil.rmtree(_cwd / "logs", ignore_errors=True)

    for f in [f"{target}.i64", f"{target}.asm"]:
        p = _cwd / Path(f)
        if p.exists():
            (shutil.rmtree(p) if p.is_dir() else p.unlink())

    for ql_file in _cwd.glob("*.ql"):
        if ql_file.is_file():
            ql_file.unlink()


# --- Binary ---

ARCH_TO_CC = {
    "x86_32": ["gcc", "-m32"],
    "x86_64": ["gcc", "-m64"],
    "arm32": ["arm-linux-gnueabi-gcc"],
    "arm64": ["aarch64-linux-gnu-gcc"],
    "mips": ["mips64-linux-gnu-gcc"],
    # "ppc": ["powerpc-linux-gnu-gcc"],
    # "riscv": ["riscv64-linux-gnu-gcc"],
}

ARCH_TO_BIN_SUFFIX = {
    "x86_32": "x86_32",
    "x86_64": "x86_64",
    "arm32": "arm32",
    "arm64": "arm64",
    "mips": "mips",
    "ppc": "ppc64",
    "riscv": "riscv64",
}

DEFAULT_CFLAGS = ["-O0", "-nostartfiles", "-Wl,-e,main"]


def _compile(
    _cwd: Path, source: str, binary: str, arch="x86", *, cflags=None, extra_args=None
):
    """Compile a source file to a binary for a specific architecture."""
    flags = DEFAULT_CFLAGS
    if cflags:
        flags = cflags
    else:
        if extra_args:
            flags += extra_args

    cc = ARCH_TO_CC.get(arch, ["gcc"])
    cmd = cc + flags + ["-o", binary, source]

    print(f"[+] Compiling {source} to {binary} for arch={arch}")
    print(f"[+] Using flags: {flags}")
    print("[+] Command:", " ".join(cmd))

    subprocess.run(cmd, cwd=_cwd, stdout=subprocess.DEVNULL, check=True)


# --- IDA Pro ---

# --- CodeQL Database ---


def run_idat(
    idat_path: Path,
    target_name: str,
    env: dict,
    cwd: Path,
    *,
    license_file: Path | None = None,
    arch: str | None = None,
):
    """Run IDA batch analysis with optional license."""
    if license_file is None and arch is None:
        raise ValueError("Either `license_file` or `arch` must be provided")

    if license_file is None:
        from conftest import resolve_ida_license

        if arch is None:
            raise AssertionError("arch must be provided when license_file is None")

        license_file = resolve_ida_license(arch)

    cmd = [str(idat_path), "-A", "-B", target_name]

    if license_file:
        cmd.append(f"-Olicense:keyfile={license_file}")

    print("[+] Running IDA command:", cmd)
    print("[+] Working directory:", cwd)

    result = subprocess.run(cmd, cwd=cwd, env=env, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"idat failed: {result.stdout}\n{result.stderr}")

    # Clean up intermediate ASM
    asm = cwd / f"{target_name}.asm"
    if asm.exists():
        asm.unlink()


def run_binql_extraction(
    _cwd: Path,
    _env: dict,
    ida_root: Path,
    target: str,
    db_dir: Path,
    *,
    license_file: Path | None = None,
    arch: str | None = None,
):
    if license_file is None and arch is None:
        raise ValueError("Either `license_file` or `arch` must be provided")

    if license_file is None:
        from conftest import resolve_ida_license

        if arch is None:
            raise AssertionError("arch must be provided when license_file is None")

        license_file = resolve_ida_license(arch)

    _env["IDA_LICENSE"] = f"keyfile={license_file}"

    run_py = Path(__file__).resolve().parents[2] / "run.py"
    target_i64 = (_cwd / f"{target}.i64").resolve()

    subprocess.run(
        [
            sys.executable,
            str(run_py),
            "--ida",
            str(ida_root),
            "--binary",
            str(target_i64),
            "--database",
            str(db_dir),
            "--auto",
        ],
        check=True,
        cwd=_cwd,
        env=_env,
    )


# --- BQRS ---


def run_codeql_query(_cwd: Path, db_dir: Path, query):
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".ql", dir=_cwd, delete=False
    ) as tmp_file:
        assert "import binary" in query, "The CodeQL query must import binary."
        query_file = Path(tmp_file.name)
        tmp_file.write(query)

    with tempfile.NamedTemporaryFile(
        suffix=".bqrs", dir=_cwd, delete=False
    ) as bqrs_file:
        bqrs_file_path = Path(bqrs_file.name)

    # Create a temporary file for the CSV output
    with tempfile.NamedTemporaryFile(suffix=".csv", dir=_cwd, delete=False) as csv_file:
        csv_file_path = Path(csv_file.name)

    # Run the CodeQL query
    try:
        subprocess.run(
            [
                "codeql",
                "query",
                "run",
                str(query_file),
                f"--database={db_dir!s}",
                "-o",
                str(bqrs_file_path),
            ],
            check=True,
            cwd=_cwd,
        )
        print(f"Query ran successfully. BQRS output saved to {bqrs_file_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error running CodeQL query: {e}")
    finally:
        query_file.unlink(missing_ok=True)

    # Decode BQRS to CSV
    try:
        subprocess.run(
            [
                "codeql",
                "bqrs",
                "decode",
                str(bqrs_file_path),
                "--format=csv",
                "--output",
                str(csv_file_path),
                "--no-titles",
            ],
            check=True,
            cwd=_cwd,
        )
        print(f"BQRS decoded successfully. CSV output saved to {csv_file_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error decoding BQRS to CSV: {e}")
    finally:
        bqrs_file_path.unlink(missing_ok=True)

    # Load the CSV as a matrix to assert values
    matrix = load_csv_matrix(csv_file_path)
    csv_file_path.unlink(missing_ok=True)
    assert matrix, "CodeQL query returns nothing..."
    return matrix


# --- All in one ---


@contextmanager
def _binary_lock(target_binary: Path):
    """Serialize compile+extract for a given prebuilt binary across pytest-xdist workers."""
    lock_path = target_binary.with_suffix(target_binary.suffix + ".lock")
    with open(lock_path, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def compile_extract(
    target_binary: Path,
    env: dict,
    ida_root: Path,
    *,
    db_dir: Path,
    license_file: Path | None = None,
    arch: str | None = None,
):
    if not target_binary.exists():
        raise FileNotFoundError(target_binary)

    test_dir = target_binary.parent
    binary_name = target_binary.name

    with _binary_lock(target_binary):
        cleanup(test_dir, binary_name)

        run_idat(
            ida_root / "idat",
            binary_name,
            env,
            test_dir,
            license_file=license_file,
            arch=arch,
        )

        run_binql_extraction(
            test_dir,
            env,
            ida_root,
            binary_name,
            db_dir,
            license_file=license_file,
            arch=arch,
        )
