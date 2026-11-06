import importlib.util
import os
import time
from pathlib import Path

import pytest
from dotenv import load_dotenv
from utils.helpers import compile_extract, find_ida_root

load_dotenv(Path(__file__).parent / ".env")

MANAGE_PY = Path(__file__).parent.parent / "manage.py"
INSTALL_HINT = "run: cd extractor && uv run manage.py install"


def _load_manage():
    spec = importlib.util.spec_from_file_location("manage", MANAGE_PY)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pytest_sessionstart(session):
    """Fail fast when BinQL is missing from, or stale in, the CodeQL install."""
    if hasattr(session.config, "workerinput"):
        return  # xdist worker: the controller already checked

    manage = _load_manage()
    try:
        codeql_home = manage.find_codeql_home()
    except FileNotFoundError as exc:
        raise pytest.UsageError(str(exc)) from None

    # UsageError prints a single "ERROR: <msg>" line, unlike pytest.exit
    if not (codeql_home / "binary").is_dir():
        raise pytest.UsageError(f"BinQL not installed in {codeql_home}, {INSTALL_HINT}")

    drift = manage.install_drift(codeql_home)
    if drift:
        more = f" (+{len(drift) - 3} more)" if len(drift) > 3 else ""
        raise pytest.UsageError(
            f"BinQL install in {codeql_home} is stale "
            f"({', '.join(drift[:3])}{more}), {INSTALL_HINT}"
        )


def parametrize_binary(argname, values):
    return pytest.mark.parametrize(
        argname,
        values,
        indirect=True,
        ids=lambda val: f"{val[0]}" if isinstance(val, (list, tuple)) else str(val),
    )


def test_dir() -> Path:
    """Directory containing this conftest (the tests root)."""
    return Path(__file__).parent


@pytest.fixture(scope="session")
def env() -> dict:
    """Copy of os.environ with TERM=xterm, for consistent subprocess terminal behavior."""
    env_vars = os.environ.copy()
    env_vars["TERM"] = "xterm"
    return env_vars


@pytest.fixture
def codeql_db_dir(request, ida_version, arch) -> Path:
    """Create `<test_dir>/databases/<test_name>_IDA-<version>_arch-<arch>`."""
    test_dir = Path(request.fspath).parent
    db_root = test_dir / "databases"

    test_name = request.node.name.split("[", 1)[0]
    db_name = f"{test_name}_IDA-{ida_version}_arch-{arch}"
    db_dir = db_root / db_name

    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir


@pytest.fixture(
    scope="session",
    params=["9.0", "9.1", "9.2", "9.3", "9.4", "9.5"],
    ids=lambda v: f"IDA-{v}",
)
def ida_version(request) -> str:
    """IDA Pro version under test."""
    return request.param


@pytest.fixture(scope="session")
def ida_root(ida_version: str) -> Path:
    """Installation root of `ida_version` under the home directory."""
    return find_ida_root(Path.home(), version=ida_version)


@pytest.fixture(
    scope="module",
    params=[
        "x86_32",
        "x86_64",
        "arm32",
        "arm64",
        "ppc32",
        "ppc64",
        "mips32",
        "mips64",
        "riscv64",
    ],
    ids=lambda v: f"arch-{v}",
)
def arch(request) -> str:
    """Target architecture under test."""
    return request.param


ARCH_TO_LICENSE_FAMILY = {
    "x86_32": "X86",
    "x86_64": "X86",
    "arm32": "ARM",
    "arm64": "ARM",
    "mips32": "MIPS",
    "mips64": "MIPS",
    "ppc32": "PPC",
    "ppc64": "PPC",
    "riscv64": "RISCV",
}


def resolve_ida_license(arch: str) -> Path | None:
    """
    License path for `arch`'s family, or None for an unknown arch.

    Raises OSError when the env var is unset: passing None through makes IDA
    fail deep in a subprocess with a cryptic message.
    """
    family = ARCH_TO_LICENSE_FAMILY.get(arch)
    if not family:
        return None
    env_var = f"IDA_LICENSE_{family}"
    license_path = os.getenv(env_var)
    if not license_path:
        raise OSError(
            f"{env_var} is not set -- can't resolve an IDA license for arch={arch!r}. "
            f"Set it (see extractor/tests/.env) to a valid .hexlic path."
        )
    license_path = Path(license_path)
    if not license_path.exists():
        raise FileNotFoundError(f"{env_var} not found: {license_path}")
    return license_path


@pytest.fixture(scope="session")
def compile_extract_session(env, ida_root):
    """Return a memoized function that extracts a prebuilt binary into a CodeQL DB."""
    cache = {}

    def _compile(
        test_dir: Path,
        binary_name: str,
        *,
        arch="x86",
        db_dir: Path,
    ):
        """Extract `bin/<binary_name>_<arch>.bin`; no-op if already done this session."""
        key = (ida_root.name, test_dir, binary_name, arch, db_dir)
        if key in cache:
            print(f"[CACHE] Skipping compilation of {binary_name} for arch={arch}")
            return

        target_binary = test_dir / "bin" / f"{binary_name}_{arch}.bin"
        if not target_binary.is_file():
            raise FileNotFoundError(
                f"Prebuilt binary not found for arch={arch}: {target_binary}"
            )

        env_with_license = env.copy()
        license_file = os.getenv(f"IDA_LICENSE_{arch.upper()}")
        if license_file:
            env_with_license[f"IDA_LICENSE_{arch.upper()}"] = license_file

        start = time.perf_counter()
        compile_extract(
            target_binary, env_with_license, ida_root, db_dir=db_dir, arch=arch
        )
        elapsed = time.perf_counter() - start
        print(
            f"[TIMING] compile+extract ({binary_name}, arch={arch}) took {elapsed:.2f}s"
        )
        cache[key] = True

    return _compile


@pytest.fixture
def compiled_extracted_binary(request, compile_extract_session, arch, codeql_db_dir):
    """Extract the prebuilt binary named by `request.param`; return its DB dir."""
    test_dir = Path(request.fspath).parent

    binary_name = request.param
    if not isinstance(binary_name, str) or not binary_name:
        pytest.fail(
            f"compiled_extracted_binary: expected a non-empty string, got {binary_name!r}"
        )

    target_binary = test_dir / "bin" / f"{binary_name}_{arch}.bin"
    if not target_binary.is_file():
        pytest.fail(
            f"Prebuilt binary not found for architecture '{arch}': {target_binary}"
        )

    compile_extract_session(test_dir, binary_name, arch=arch, db_dir=codeql_db_dir)
    return codeql_db_dir
