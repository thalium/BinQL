# BinQL

A **CodeQL extractor for binaries**. BinQL runs IDA Pro's Hex-Rays decompiler headless through [idalib](https://docs.hex-rays.com/user-guide/idalib) and turns the decompiled pseudocode of any binary into a **CodeQL database**, so you can hunt for bugs in firmware and closed-source executables with the same queries and tooling you use on C/C++ source.

> [!NOTE]
> BinQL is not an interactive IDA plugin. The plugin installed by `hcli` is a stub that only prints a pointer to the real tool: the extractor runs from the command line, outside the IDA GUI.

## Quick start

Requirements: IDA Pro 9.0 or later with a Hex-Rays decompiler license, [CodeQL](https://github.com/github/codeql-action/releases?q=%22Bundles+CodeQL%22) in your `PATH`, and [uv](https://docs.astral.sh/uv/).

```bash
$ git clone https://github.com/thalium/binql
$ cd binql
$ uv run extractor/manage.py install
$ uv run extractor/run.py --ida ~/ida-pro-9.5 --binary ./ls
```

See the [main README](https://github.com/thalium/binql#readme) for installation details, writing queries, and the `binary` CodeQL library documentation.

## License

MIT, see [LICENSE](https://github.com/thalium/binql/blob/main/LICENSE).
