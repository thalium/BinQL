"""Stub entry point so BinQL can be listed in the IDA plugin repository; the real extractor runs headless under idalib."""

import idaapi  # ty: ignore[unresolved-import]


class BinqlExtractorStub(idaapi.plugin_t):
    flags = 0
    comment = "Stub for BinQL (headless CodeQL binary extractor, runs via idalib)"
    help = "This plugin is a stub and does not provide any functionality."
    wanted_name = "BinQL"
    wanted_hotkey = ""

    def init(self):
        print(  # noqa: T201
            "[WARN] BinQL is a headless CodeQL extractor, not an interactive IDA "
            "plugin. Run it via `uv run extractor/run.py`.",
        )
        return idaapi.PLUGIN_SKIP

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return BinqlExtractorStub()
