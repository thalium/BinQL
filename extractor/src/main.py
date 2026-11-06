"""BinQL extractor entry point; BINQL_PROFILE=1 writes a pyinstrument HTML profile."""

if __name__ == "__main__":
    import os
    import sys

    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr]  # ty: ignore[unresolved-attribute]

    try:
        import idapro  # noqa: F401
    except ImportError as exc:
        print("extractor: failed to import idapro:", exc)  # noqa: T201
        sys.exit(1)

    from decompiler.ida.main import visitor_main

    if os.environ.get("BINQL_PROFILE"):
        from pyinstrument import Profiler

        profiler = Profiler()
        profiler.start()
        visitor_main()
        profiler.stop()
        profiler.write_html(
            os.environ.get("CODEQL_EXTRACTOR_BINARY_WIP_DATABASE", "/tmp")
            + "/log/profiler-pyinstrument.html",
            timeline=False,
            show_all=False,
        )
    else:
        visitor_main()

    sys.exit(0)
