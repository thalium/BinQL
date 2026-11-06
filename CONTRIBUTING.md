# Contributing to BinQL

Thanks for your interest in BinQL! Bug reports, queries, fixes and new features are all welcome.
This document explains how to report problems and how contributions find their way into a release.

## Reporting bugs

Before opening an issue, check the existing ones to avoid duplicates. A good bug report includes:

* What you ran (the full `run.py` or `codeql` command) and what you expected
* Your environment: OS, Python, IDA Pro and CodeQL bundle versions, target architecture
* The extractor log of the database: `databases/<name>/log/extractor/` (`error` and `warning` files)
* For a wrong or missing query result: the query, the address (`getEA()`) of the code involved, and the Hex-Rays pseudocode of the function
* If you can share it, the binary or a minimal C file that reproduces the problem

> [!NOTE]
> Pseudocode missing from the database usually shows up as an `ERROR` line in the extractor log. Including those lines is the fastest way to get it fixed.

## Suggesting features

Open an issue describing the use case, ideally with the query you would like to write. For new library classes or predicates, say which class of the [CodeQL library for C/C++](https://codeql.github.com/codeql-standard-libraries/cpp/) you would expect it to mirror: BinQL follows its names whenever it can.

## Pull requests

BinQL is developed in an internal repository and published to GitHub at each release. Pull requests are reviewed here on GitHub as usual, but they are **not merged on GitHub**:

1. Open your pull request against `main`. Discussion and review happen on the pull request.
2. Once it is accepted, we import it into the internal repository with your authorship kept, run the full test suite (it needs IDA licenses for every architecture, see [Running the tests](#running-the-tests)), and merge it there.
3. The change is published with the next release, and the pull request is closed with a link to that release.

Keep pull requests focused on one change, add or update a test when the extractor or the library changes, and make sure the linters pass.

By contributing, you agree that your contributions are licensed under the project's [MIT license](LICENSE).

## Development

### Prerequisites

* Python 3.10 or later and [uv](https://docs.astral.sh/uv/)
* IDA Pro 9.0 or later with a Hex-Rays decompiler license
* A CodeQL bundle with `codeql` in your `PATH`
* Docker, to build the test binaries

### Setting up

```bash
$ git clone https://github.com/thalium/binql
$ cd binql
$ uv run extractor/manage.py install
```

`manage.py install` copies the extractor and the `thalium/binary` library into your CodeQL installation, and `codeql database create` only ever uses that installed copy. **Run it again after every change** under `extractor/` or `qlpack/`, before extracting or running the tests, or you will be testing the previous version.

### Project layout

```
binql/
├── extractor/                # Python extractor, runs under idalib
│   ├── run.py                # Command-line entry point
│   ├── manage.py             # install / docs
│   ├── src/
│   │   ├── decompiler/ida/   # Hex-Rays ctree walk and TRAP emission
│   │   └── utils/            # Logging, TRAP writing helpers
│   ├── tools/                # CodeQL autobuild scripts
│   └── tests/                # Extractor, library and end-to-end tests
└── qlpack/1.0.0/             # The thalium/binary CodeQL library
    ├── binary.dbscheme       # Database schema, must match extractor/binary.dbscheme
    └── thalium/              # QL classes
```

### Linters

The project uses [prek](https://github.com/j178/prek) (ruff, ty, and a check that both copies of `binary.dbscheme` are identical):

```bash
$ uvx prek run -c extractor/.pre-commit-config.yaml --all-files
```

### Running the tests

Each test compiles a small C program for every architecture, extracts it with every supported IDA version, and runs queries on the database.

1. Point the tests to your Hex-Rays licenses, one per decompiler family:

   ```bash
   $ cp extractor/tests/.env.example extractor/tests/.env   # then edit the paths
   ```

   IDA installations are looked up in your home directory, one per version (`~/ida-pro-9.5`, ...).

2. Build the test binaries (cross-compilers run in Docker):

   ```bash
   $ cd extractor/tests
   $ make clean-subdirs all
   ```

3. Install BinQL, then run a test file or directory. Use `-n auto --dist=loadscope` so the tests sharing a database stay on the same worker, and `-k` to limit the IDA versions and architectures:

   ```bash
   $ uv run extractor/manage.py install
   $ cd extractor/tests
   $ uv run pytest -n auto --dist=loadscope ida/unit/statement -k "9.5 and x86_64"
   ```

### Supporting a new ctree node type

Hex-Rays represents pseudocode as a tree of `cot_*` (expressions) and `cit_*` (statements) nodes. To extract a node type BinQL does not handle yet (see the opcodes in `extractor/src/decompiler/ida/utils.py`):

1. Write a C file in `extractor/tests/ida/unit/<topic>/src/` that produces the node.
2. Build it and check in IDA that Hex-Rays really decompiles it to the expected ctree node: compilers often fold or rewrite simple code.
3. Handle the node in the extractor (`extractor/src/decompiler/ida/handlers.py`) and, if it needs a new table, in both copies of `binary.dbscheme`.
4. Add or extend the QL class in `qlpack/1.0.0/thalium/`, mirroring the C/C++ library's name and predicates.
5. Write the test in `test_<topic>.py`, rebuild the binaries and run it.

## Style

* **Python**: formatted and linted with ruff, type-checked with ty. Add type hints and a docstring to new functions.
* **QL**: every public class and predicate gets a doc comment, since they make up the [generated library documentation](README.md#library-documentation). Prefer the class and predicate names of the CodeQL library for C/C++.
* **Commit messages**: [Conventional Commits](https://www.conventionalcommits.org/), with the component as scope, for example `fix(IDA/handlers): ...`, `feat(ql): ...`, `tests(IDA): ...`, `docs: ...`.

## License

BinQL is released under the [MIT license](LICENSE).
