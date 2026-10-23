#!/usr/bin/env python3
"""CoreCleaner entry point. One script, one subcommand per step; stdout is always one JSON document.

    python3 corecleaner.py [--pretty] <check|free|bootstrap|scan|inventory|plan|ask|trash|undo|report|repos|migrate-plan|migrate> [...]

Success: {"ok": true, "cmd": ..., ...module result}. Failure: {"ok": false, "error": {code, name,
message}} with the same code as the process exit status. Logs go to stderr. Contract: docs/SPEC.md.
One exception: `trash` with a requested id that is not ok prints its normal {"ok": true, ...} document and exits 46.
Every subcommand calls corecleaner_lib.<module>.run(args); see COMMANDS.
"""

import sys

if sys.version_info < (3, 9):
    sys.stderr.write("corecleaner needs Python 3.9 or newer\n")
    sys.exit(1)

import argparse
import importlib
import os
import traceback
from typing import List, Optional

_HERE = os.path.dirname(os.path.realpath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from corecleaner_lib import common, views  # noqa: E402

# subcommand -> corecleaner_lib module that serves it via run(args)
COMMANDS = {
    "check": "platform_info",
    "free": "platform_info",
    "bootstrap": "bootstrap",
    "scan": "scan",
    "inventory": "inventory",
    "plan": "plan",
    "ask": "ask",
    "trash": "trash",
    "undo": "trash",
    "report": "report",
    "settings": "settings",
    "repos": "repos",
    "migrate-plan": "migrate",
    "migrate": "migrate",
}

# Read-only diagnosis that may run as root/admin; everything else refuses (SPEC trava 8).
ROOT_OK = frozenset({"check", "free"})

WINDOWS_BETA = "Windows support is BETA and untested"

# scan and inventory carry raw file names: stdout gets a sanitized summary, the full JSON is saved (trava 9).
SUMMARIZED = frozenset({"scan", "inventory"})
SCRUBBED = frozenset({"check", "undo", "trash", "repos", "migrate-plan", "migrate"})  # OS-supplied names, reasons
RAW_HELP = "print the full result with raw names (for a person at a terminal, never feed it to an agent)"


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # keep stdout JSON-only: no usage dump on stderr
        raise common.CorecleanerError(common.EXIT_USAGE, message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="corecleaner.py", description="CoreCleaner " + common.VERSION)
    parser.add_argument("--pretty", action="store_true", help="indent the JSON output")
    parser.add_argument("--version", action="version", version="corecleaner " + common.VERSION)
    sub = parser.add_subparsers(dest="cmd", required=True, metavar="<command>")

    # --pretty is also accepted after the subcommand; SUPPRESS keeps the top-level value.
    after = _Parser(add_help=False)
    after.add_argument("--pretty", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        return sub.add_parser(name, help=help_text, parents=[after])

    add("check", "OS, arch, Python, Trash, dua, git, volumes (read-only)")
    p = add("free", "free bytes of the volume holding PATH (read-only)")
    p.add_argument("--path", default=None, help="default: HOME")

    p = add("bootstrap", "install the pinned dua into the state dir after sha256 check")
    p.add_argument("--yes", action="store_true", help="consent given; without it only describes")
    p.add_argument("--decline", action="store_true", help="record the user's no in settings.json so it is not asked again")

    p = add("scan", "disk map as JSON tree plus GAP line (read-only)")
    p.add_argument("--roots", nargs="+", default=None, metavar="PATH", help="default: OS roots")
    p.add_argument("--no-dua", action="store_true", help="force basic mode (upper-bound sizes)")
    p.add_argument("--timeout", type=int, default=None, metavar="SECONDS", help="per dua call (default 540; env CORECLEANER_SCAN_TIMEOUT)")
    p.add_argument(
        "--max-seconds", type=int, default=None, metavar="SECONDS",
        help="wall-clock budget of the whole dua scan; what is left unread is reported as not measured (env CORECLEANER_SCAN_MAX_SECONDS)",
    )
    p.add_argument("--ask-finder", action="store_true", help="macOS: let Finder size the Trash when it cannot be read (may show a permission prompt)")
    p.add_argument("--raw", action="store_true", help=RAW_HELP)

    p = add("inventory", "cleanup candidates A-L with evidence (read-only)")
    p.add_argument("--raw", action="store_true", help=RAW_HELP)

    p = add("plan", "write plan-<ts>.json (ids, realpath, bytes, inode, mtime, sha256) to the state dir")
    p.add_argument("--candidates", default=None, metavar="FILE", help="inventory JSON; default: run inventory")

    p = add("ask", "render the questions for a plan, in batches, names sanitized")
    p.add_argument("--plan", required=True, metavar="FILE")
    p.add_argument("--format", choices=("claude", "codex", "text"), default="text")
    p.add_argument("--expand", default=None, metavar="GROUPS", help="1, 2 or 1,2: ask item by item for those groups")
    p.add_argument("--lang", default=None, metavar="LANG", help="en (default) or pt; env CORECLEANER_LANG")
    p.add_argument("--reply", default=None, metavar="TEXT", help="the text copied from the report: prints the ids per action, checked against the plan")

    p = add("trash", "move approved plan ids to the OS Trash (dry-run unless --apply)")
    p.add_argument("--plan", required=True, metavar="FILE")
    p.add_argument("--ids", nargs="+", required=True, metavar="ID", help="space or comma separated")
    p.add_argument("--apply", action="store_true", help="actually move; default is dry-run")

    p = add("undo", "restore a run from its manifest")
    p.add_argument("--run", required=True, metavar="RUN_ID")

    p = add("report", "write report.html (the plan's junk by folder, plus the disk map; offline) to the state dir")
    p.add_argument("--scan", required=True, metavar="FILE", help="saved `scan` JSON")
    p.add_argument("--plan", default=None, metavar="FILE", help="plan file: without it the page is only the disk map")
    p.add_argument("--lang", default=None, metavar="LANG", help="en or pt; default: settings.json, then CORECLEANER_LANG")

    p = add("settings", "show or record the user's choices (language, dua) in the state dir")
    p.add_argument("--lang", default=None, choices=("en", "pt"), help="language for ask and report")
    p.add_argument("--dua", default=None, choices=("declined", "ask"), help="declined: never offer dua again; ask: forget that")

    p = add("repos", "audit the git repos under HOME, biggest first; saves a signed repos file (read-only)")
    p.add_argument("--roots", nargs="+", default=None, metavar="PATH", help="default: HOME")
    p.add_argument("--min-days", type=int, default=45, metavar="DAYS", help="idle days before a repo is offered (default 45)")

    p = add("migrate-plan", "check an external-disk folder and write migrate-<ts>.json for the repos file")
    p.add_argument("--repos", required=True, metavar="FILE", help="the file `repos` saved")
    p.add_argument("--to", required=True, metavar="DIR", help="folder on the external disk")

    p = add("migrate", "copy approved repos to the disk, verify, then Trash the originals (dry-run unless --apply)")
    p.add_argument("--plan", required=True, metavar="FILE")
    p.add_argument("--ids", nargs="+", required=True, metavar="ID", help="space or comma separated")
    p.add_argument("--apply", action="store_true", help="actually copy and move; default is dry-run")
    p.add_argument("--push-owners", default=None, metavar="A,B", help="owners allowed to receive arquivo-* tags: owner (= github.com/owner) or host/owner; none = nothing is pushed")
    return parser


def load_module(short_name: str):
    return importlib.import_module("corecleaner_lib." + short_name)


def _decorate(obj: dict) -> dict:
    if sys.platform == "win32":
        obj.setdefault("warnings", []).append(WINDOWS_BETA)
    return obj


def _normalize_ids(args: argparse.Namespace) -> None:
    ids: Optional[List[str]] = getattr(args, "ids", None)
    if ids is not None:
        args.ids = [part for chunk in ids for part in chunk.split(",") if part]


def _utf8_streams() -> None:
    """The JSON is read as UTF-8 by the agent. A pipe on a legacy code page (Windows cp1252) would encode
    `Joao` with an accent as one byte, which is not valid UTF-8; backslashreplace keeps bad names printable."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="backslashreplace")
            except (OSError, ValueError):
                pass


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    _utf8_streams()
    cmd = None
    pretty = False
    try:
        args = build_parser().parse_args(argv)
        cmd = args.cmd
        pretty = bool(getattr(args, "pretty", False))
        _normalize_ids(args)
        if cmd not in ROOT_OK and common.is_admin():
            raise common.CorecleanerError(
                common.EXIT_ROOT_REFUSED,
                "refusing to run as root/administrator; run as your normal user (corecleaner never uses sudo)",
            )
        if getattr(args, "raw", False) and not sys.stdout.isatty() and os.environ.get("CORECLEANER_ALLOW_RAW") != "1":
            raise common.CorecleanerError(common.EXIT_USAGE, "--raw is for a person at a terminal (CORECLEANER_ALLOW_RAW=1 overrides)")
        result = load_module(COMMANDS[cmd]).run(args)
        if cmd in SUMMARIZED and not getattr(args, "raw", False) and isinstance(result, dict):
            result = views.agent_view(cmd, result)
        elif cmd in SCRUBBED and isinstance(result, dict):
            result = views.scrub(result)
        out = {"ok": True, "cmd": cmd}
        out.update(result if isinstance(result, dict) else {"result": result})
        common.emit(_decorate(out), pretty)
        # `trash` printed every row; a requested id that is not ok (deny, failed, skipped) still shows in the status
        return common.EXIT_PARTIAL if cmd == "trash" and out.get("not_ok") else common.EXIT_OK
    except common.CorecleanerError as exc:
        common.log(exc.message)
        extra = {"cmd": cmd}
        if exc.details:  # an error can quote a name from any command (a plan path, a --roots argument)
            extra["error_details"] = views.scrub(exc.details)
        common.emit(_decorate(common.error_obj(exc.code, views.scrub(exc.message), **extra)), pretty)
        return exc.code
    except NotImplementedError:
        msg = "subcommand '%s' is not implemented yet" % cmd
        common.log(msg)
        common.emit(
            _decorate(common.error_obj(common.EXIT_ERROR, msg, name="not_implemented", cmd=cmd)), pretty
        )
        return common.EXIT_ERROR
    except KeyboardInterrupt:
        common.emit(_decorate(common.error_obj(130, "interrupted", name="interrupted", cmd=cmd)), pretty)
        return 130
    except Exception as exc:  # last resort: still JSON on stdout, trace on stderr
        for line in traceback.format_exc().splitlines():  # the last line quotes the exception text, which can hold a name
            common.log(line)
        msg = views.scrub("%s: %s" % (type(exc).__name__, exc))
        common.emit(_decorate(common.error_obj(common.EXIT_ERROR, msg, name="internal", cmd=cmd)), pretty)
        return common.EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
