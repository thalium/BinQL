#!/usr/bin/env python3

import argparse
import filecmp
import json
import logging
import re
import shutil
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Where the thalium/binary qlpack is installed, relative to the CodeQL home.
QLPACK_INSTALL_DIR = Path("qlpacks") / "thalium" / "binary-all"
# Install dir from before the pack was renamed from codeql/binary; removed on install.
LEGACY_QLPACK_INSTALL_DIR = Path("qlpacks") / "codeql" / "binary-all"
# Written into the installed extractor by `install`: BinQL version and commit.
BUILD_INFO = "binql-build.json"

# Top-level entries under extractor/ that the installed CodeQL extractor needs.
# Everything else (tests/, run.py, manage.py, dev configs, caches) is skipped.
EXTRACTOR_INCLUDE = {
    "binary.dbscheme",
    "binary.dbscheme.stats",
    "codeql-extractor.yml",
    "pyproject.toml",
    "uv.lock",
    "src",
    "tools",
}

# Basenames pruned anywhere in a copied tree (caches, venvs, generated docs).
PRUNE_NAMES = {
    ".git",
    ".claude",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "logs",
    "docs",
}

logger = logging.getLogger(__name__)

REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r">Qldoc</div>"), r">CodeQL library for Binary</div>"),
    (
        re.compile(
            r'<div class="Header-item"><a title="Search the CodeQL libraries" target="_blank" href="https://codeql.github.com/codeql-standard-libraries/search.html"><span class=".text-gray-light">Search</span></a></div>'
        ),
        "",
    ),
    (
        re.compile(
            r'<div class="Header-item"><svg class="octicon octicon-mark-github mr-2".*?</svg></div>',
            re.DOTALL,
        ),
        "",
    ),
    (
        re.compile(
            r'<p>For other CodeQL resources, including tutorials and examples, see the <a href="https://codeql.github.com/docs/" class="codeql-link" target="_blank">CodeQL documentation</a><p>.</p></p>'
        ),
        "",
    ),
    (
        re.compile(
            r'Copyright\s+\d{4}\s+GitHub Software UK Ltd\.<a title="Privacy statement and tracking preferences" target="_blank" href="https://docs.github.com/github/site-policy/github-privacy-statement">Privacy Statement</a>'
        ),
        r'Inspired from <a title="library for C/C++" target="_blank" href="https://codeql.github.com/codeql-standard-libraries/cpp">CodeQL library for C/C++</a> <span style="padding-left: 13px;">by</span> <a title="Thalium Team" target="_blank" href="https://thalium.re/">Thalium Team</a>',
    ),
]


# Utils


def find_codeql_home() -> Path:
    codeql = shutil.which("codeql")
    if not codeql:
        raise FileNotFoundError("codeql not found in PATH")
    return Path(codeql).resolve().parent


def delete_path(path: Path) -> None:
    if not path.exists():
        return

    try:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    except Exception as exc:
        raise RuntimeError(f"Failed to delete {path}") from exc


def _pruned(rel: Path) -> bool:
    return any(part in PRUNE_NAMES for part in rel.parts) or rel.suffix == ".pyc"


def copy_tree(src: Path, dst: Path, keep: Callable[[Path], bool] | None = None) -> None:
    if not src.exists():
        raise FileNotFoundError(f"Source directory not found: {src}")

    dst.mkdir(parents=True, exist_ok=True)

    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        if _pruned(rel) or (keep is not None and not keep(rel)):
            continue

        target = dst / rel
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def _tree_drift(
    src: Path, dst: Path, keep: Callable[[Path], bool] | None = None
) -> list[Path]:
    """Files under `src` missing from, or differing in, its installed copy `dst`."""
    drift = []
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        if path.is_dir() or _pruned(rel) or (keep is not None and not keep(rel)):
            continue
        target = dst / rel
        if not target.is_file() or not filecmp.cmp(path, target):
            drift.append(rel)
    return drift


def _keep_extractor(rel: Path) -> bool:
    return rel.parts[0] in EXTRACTOR_INCLUDE


def install_drift(codeql_home: Path) -> list[str]:
    """Paths where the BinQL install under `codeql_home` differs from this checkout."""
    drift = [
        f"extractor/{rel}"
        for rel in _tree_drift(
            ROOT / "extractor", codeql_home / "binary", keep=_keep_extractor
        )
    ]
    qlpack_dst = codeql_home / QLPACK_INSTALL_DIR
    for sub in sorted((ROOT / "qlpack").iterdir()):
        if sub.is_dir():
            drift += [
                f"qlpack/{sub.name}/{rel}"
                for rel in _tree_drift(sub, qlpack_dst / sub.name)
            ]
    return drift


def get_versions() -> list[str]:
    ql_root = ROOT / "qlpack"
    return sorted(d.name for d in ql_root.iterdir() if d.is_dir())


def _read_version(path: Path, pattern: str) -> str | None:
    """First group of the first line of `path` matching `pattern`, or None."""
    match = re.search(pattern, path.read_text(), re.MULTILINE)
    return match.group(1) if match else None


def version_mismatches() -> list[str]:
    """Versions that disagree between the extractor, its qlpacks and the packaging files."""
    errors = []

    extractor_yml = ROOT / "extractor" / "codeql-extractor.yml"
    version = _read_version(extractor_yml, r"^version:\s*(\S+)")
    if version is None:
        return [f"no version in {extractor_yml.relative_to(ROOT)}"]

    # Every qlpack/<v>/ declares version <v>.
    for qlpack_version in get_versions():
        qlpack_yml = ROOT / "qlpack" / qlpack_version / "qlpack.yml"
        declared = _read_version(qlpack_yml, r"^version:\s*(\S+)")
        if declared != qlpack_version:
            errors.append(
                f"{qlpack_yml.relative_to(ROOT)} declares version {declared}, "
                f"expected {qlpack_version} (its directory)"
            )

    # The extractor's version has its qlpack, with the same dbscheme.
    qlpack_dir = ROOT / "qlpack" / version
    if not qlpack_dir.is_dir():
        errors.append(f"extractor version {version} has no qlpack/{version}/")
    elif not filecmp.cmp(
        ROOT / "extractor" / "binary.dbscheme",
        qlpack_dir / "binary.dbscheme",
        shallow=False,
    ):
        errors.append(
            f"extractor/binary.dbscheme differs from qlpack/{version}/binary.dbscheme"
        )

    # Packaging files carry the extractor's version.
    others = {
        "extractor/pyproject.toml": _read_version(
            ROOT / "extractor" / "pyproject.toml", r'^version\s*=\s*"([^"]+)"'
        ),
        "extractor/plugin/ida/ida-plugin.json": json.loads(
            (ROOT / "extractor" / "plugin" / "ida" / "ida-plugin.json").read_text()
        )["plugin"]["version"],
    }
    for name, other in others.items():
        if other != version:
            errors.append(f"{name} has version {other}, expected {version}")

    return errors


def _git(*args: str) -> str | None:
    """Output of `git <args>` in the repository, or None if git or the repository is missing."""
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def write_build_info(path: Path) -> None:
    """Record the BinQL version and commit being installed; the extractor copies it into each database."""
    status = _git("status", "--porcelain", "--untracked-files=no")
    info = {
        "version": _read_version(
            ROOT / "extractor" / "codeql-extractor.yml", r"^version:\s*(\S+)"
        ),
        "commit": _git("rev-parse", "HEAD"),
        "dirty": bool(status) if status is not None else None,
    }
    path.write_text(json.dumps(info, indent=2) + "\n")


# Commands


def install_binql(codeql_home: Path) -> None:
    logger.info("Installing BinQL into %s", codeql_home)

    delete_path(codeql_home / "binary")
    delete_path(codeql_home / QLPACK_INSTALL_DIR)
    delete_path(codeql_home / LEGACY_QLPACK_INSTALL_DIR)

    extractor_dst = codeql_home / "binary"
    copy_tree(
        ROOT / "extractor",
        extractor_dst,
        keep=_keep_extractor,
    )
    write_build_info(extractor_dst / BUILD_INFO)

    ql_root = ROOT / "qlpack"
    qlpack_dst = codeql_home / QLPACK_INSTALL_DIR
    qlpack_dst.mkdir(parents=True, exist_ok=True)

    for sub in ql_root.iterdir():
        if sub.is_dir():
            copy_tree(sub, qlpack_dst / sub.name)

    logger.info("BinQL installed successfully")
    logger.info("  extractor -> %s", extractor_dst)
    logger.info("  qlpack    -> %s", qlpack_dst)


def generate_docs(requested_version: str | None = None) -> None:
    if not shutil.which("codeql"):
        raise FileNotFoundError("codeql not found in PATH")

    available = get_versions()
    logger.info("Available versions: %s", available)

    if requested_version:
        if requested_version not in available:
            raise ValueError(
                f"Version '{requested_version}' not found. Available: {available}"
            )
        versions: Iterable[str] = [requested_version]
    else:
        versions = available

    pack_path = ROOT / "qlpack"

    for version in versions:
        logger.info("Generating documentation for %s:", version)

        version_path = pack_path / version
        docs_path = version_path / "docs"

        delete_path(docs_path)

        try:
            subprocess.run(
                ["codeql", "generate", "library-doc", "--output=docs"],
                cwd=version_path,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as exc:
            logger.error("Failed to generate docs for %s", version)
            raise SystemExit(exc.returncode) from exc

        for html in docs_path.rglob("*.html"):
            text = html.read_text()
            for pattern, repl in REPLACEMENTS:
                text = pattern.sub(repl, text)
            html.write_text(text)

        logger.info("Docs generated: %s", (docs_path / "index.html").as_uri())


# CLI


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="manage.py",
        description="Manage BinQL installation and documentation generation.",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    inst = sub.add_parser("install", help="Install BinQL into CodeQL.")
    inst.add_argument(
        "--codeql-home",
        type=Path,
        help="Path to CodeQL installation (auto-detected if omitted).",
    )

    docs = sub.add_parser("docs", help="Generate Binary qlpack documentation.")
    docs.add_argument(
        "--version",
        help="QLPack version to generate docs for (default: all).",
    )

    sub.add_parser(
        "check-versions",
        help="Check that the extractor, qlpack and packaging versions match.",
    )

    all_cmd = sub.add_parser("all", help="Install BinQL and generate documentation.")
    all_cmd.add_argument(
        "--codeql-home",
        type=Path,
        help="Path to CodeQL installation (auto-detected if omitted).",
    )
    all_cmd.add_argument(
        "--version",
        help="QLPack version to generate docs for (default: all).",
    )

    args = parser.parse_args()

    try:
        if args.cmd == "install":
            home = args.codeql_home or find_codeql_home()
            install_binql(home)

        elif args.cmd == "docs":
            generate_docs(args.version)

        elif args.cmd == "check-versions":
            errors = version_mismatches()
            for error in errors:
                logger.error("%s", error)
            return 1 if errors else 0

        elif args.cmd == "all":
            home = args.codeql_home or find_codeql_home()
            install_binql(home)
            generate_docs(args.version)

        return 0

    except Exception as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
