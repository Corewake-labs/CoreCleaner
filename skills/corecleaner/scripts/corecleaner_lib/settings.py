"""`settings`: show or change what the user decided once (language, dua). Writes only settings.json in the state dir."""

from typing import Any

from . import common

LANGS = ("en", "pt")


def run(args: Any) -> dict:
    changes = {}
    lang = getattr(args, "lang", None)
    if lang is not None:
        if lang not in LANGS:
            raise common.CorecleanerError(common.EXIT_USAGE, "lang must be one of: " + ", ".join(LANGS))
        changes["lang"] = lang
    dua = getattr(args, "dua", None)
    if dua is not None:
        changes["dua"] = None if dua == "ask" else dua
    data = common.write_settings(**changes) if changes else common.read_settings()
    return {"settings": data, "file": str(common.settings_path()), "changed": sorted(changes)}
