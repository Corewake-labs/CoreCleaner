"""Shared helpers for every corecleaner module: version, exit codes, state dir, JSON output.

Contract for all modules (`corecleaner_lib/<module>.py`):
  * A module that serves a subcommand exposes `run(args: argparse.Namespace) -> dict`.
    `args.cmd` is the subcommand name (platform_info and trash serve two each).
  * `run` returns a JSON-serializable dict; corecleaner.py wraps it in {"ok": true, "cmd": ...}
    and prints it. Modules never print to stdout themselves; logs go to `log()` (stderr).
  * Failure = raise `CorecleanerError(code, message, **details)`; never `sys.exit` from a module.
  * Never call os.remove / os.unlink / shutil.rmtree on a user path. Only the OS Trash.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn, Optional

VERSION = "0.1.0"

# Env override of the state directory (tests, relocated installs). Never a user-data path.
STATE_ENV = "CORECLEANER_STATE_DIR"

# Exit codes. 0 ok, 1 generic, 2 usage; the rest are fixed by docs/SPEC.md.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_UNSUPPORTED_ARCH = 10
EXIT_NO_NETWORK = 11
EXIT_HASH_MISMATCH = 20
EXIT_NO_TRASH = 30
EXIT_DENYLISTED = 40
EXIT_PLAN_TAMPERED = 41
EXIT_STATE_CHANGED = 42
EXIT_LIVE_PROCESS = 43
EXIT_NO_SPACE_FOR_ARCHIVE = 44
EXIT_BAD_DESTINATION = 45  # migrate: the external-disk folder fails a check of SPEC-migrate trava 1
EXIT_PARTIAL = 46  # trash: the batch ran and printed every row, but a requested id is not ok (deny, failed or skipped)
EXIT_ROOT_REFUSED = 50  # not in SPEC's list: needed for trava 8 (refuse root/admin)

ERROR_NAMES = {
    EXIT_ERROR: "error",
    EXIT_USAGE: "usage",
    EXIT_UNSUPPORTED_ARCH: "unsupported_arch",
    EXIT_NO_NETWORK: "no_network",
    EXIT_HASH_MISMATCH: "hash_mismatch",
    EXIT_NO_TRASH: "no_trash",
    EXIT_DENYLISTED: "denylisted",
    EXIT_PLAN_TAMPERED: "plan_tampered",
    EXIT_STATE_CHANGED: "state_changed",
    EXIT_LIVE_PROCESS: "live_process",
    EXIT_NO_SPACE_FOR_ARCHIVE: "no_space_for_archive",
    EXIT_BAD_DESTINATION: "bad_destination",
    EXIT_PARTIAL: "partial",
    EXIT_ROOT_REFUSED: "root_refused",
}


class CorecleanerError(Exception):
    """Controlled failure. `code` becomes the process exit code."""

    def __init__(self, code: int, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def error_name(code: int) -> str:
    return ERROR_NAMES.get(code, "error")


def error_obj(code: int, message: str, name: Optional[str] = None, **extra: Any) -> dict:
    """The one error shape printed on stdout: {"ok": false, "error": {code, name, message}}."""
    obj: dict = {
        "ok": False,
        "error": {"code": code, "name": name or error_name(code), "message": message},
    }
    obj.update(extra)
    return obj


LOG_MAX = 300


def log(message: str) -> None:
    """One stderr line. A message can carry an OS-supplied name, and stderr reaches the agent too, so it
    is data: controls, bidi and invisible characters are replaced and the line is cut at LOG_MAX."""
    from . import safety  # late: safety imports this module

    sys.stderr.write("corecleaner: " + safety.sanitize_name(message, LOG_MAX) + "\n")
    sys.stderr.flush()


REQUIRE_TTY_ENV = "CORECLEANER_REQUIRE_TTY_APPLY"
NO_HUMAN_WARNING = (
    "no proof a person answered: stdout is not a terminal, so nothing shows a person approved this --apply "
    "(%s=1 refuses --apply off a terminal)" % REQUIRE_TTY_ENV
)


def apply_guard(apply: bool) -> list:
    """trash and migrate call this first. Nothing ties --apply to a person's answer: in a bypass or full-auto
    mode an agent can pass it unasked. Off a terminal it returns a warning for the result; with
    CORECLEANER_REQUIRE_TTY_APPLY=1 it refuses, and a person runs --apply in their own terminal."""
    if not apply or sys.stdout.isatty():
        return []
    if os.environ.get(REQUIRE_TTY_ENV) == "1":
        raise CorecleanerError(
            EXIT_USAGE, "--apply needs a terminal: stdout is not one and %s=1 is set; run it yourself in a terminal" % REQUIRE_TTY_ENV
        )
    return [NO_HUMAN_WARNING]


def now_iso() -> str:
    """UTC, ISO-8601, seconds precision (e.g. 2026-10-21T13:48:00Z)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_stamp() -> str:
    """Filename-safe UTC stamp (20261021T134800Z) for plan-<ts>.json and run ids."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", "backslashreplace")
    raise TypeError("not JSON serializable: " + type(value).__name__)


def emit(obj: Any, pretty: bool = False) -> None:
    """Print `obj` as one JSON document on stdout (compact; indent=2 when pretty)."""
    kwargs: dict = {"indent": 2} if pretty else {"separators": (",", ":")}
    try:
        text = json.dumps(obj, ensure_ascii=False, default=_json_default, **kwargs)
        sys.stdout.write(text + "\n")
    except UnicodeEncodeError:
        # Undecodable file names surface as lone surrogates; escape them instead of crashing.
        text = json.dumps(obj, ensure_ascii=True, default=_json_default, **kwargs)
        sys.stdout.write(text + "\n")
    sys.stdout.flush()


def die(code: int, message: str, **details: Any) -> NoReturn:
    """Print the error JSON on stdout, the message on stderr, exit with `code`."""
    from . import views  # late: views imports this module

    extra = {"error_details": views.scrub(details)} if details else {}
    log(message)
    emit(error_obj(code, views.scrub(message), **extra))
    sys.exit(code)


def is_admin() -> bool:
    """True when running as root (POSIX) or an elevated Administrator (Windows)."""
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return os.geteuid() == 0


def _private_dir(path: Path) -> Path:
    if path.is_symlink():
        raise CorecleanerError(EXIT_ERROR, "state directory is a symlink; refusing", path=str(path))
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(path, 0o700)  # mkdir mode is masked by umask and skipped when it exists
    except OSError as exc:
        raise CorecleanerError(
            EXIT_ERROR, "cannot create or secure state directory: " + str(exc.strerror), path=str(path)
        )
    return path


SETTINGS_NAME = "settings.json"


def settings_path() -> Path:
    """Never creates the state dir: `check` and `ask` read settings without leaving a trace."""
    return state_dir_path() / SETTINGS_NAME


def read_settings() -> dict:
    """What the user decided once (language, dua): {} when nothing was recorded or the file is not ours to trust."""
    path = settings_path()
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return {}
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, (str, int, bool))} if isinstance(data, dict) else {}


def write_settings(**changes: Any) -> dict:
    """Merge `changes` into settings.json (0600, temp file plus rename). A None value removes the key."""
    data = read_settings()
    for k, v in changes.items():
        if v is None:
            data.pop(k, None)
        else:
            data[k] = v
    path = state_dir() / SETTINGS_NAME  # writing may create the state dir (0700)
    tmp = path.with_name(path.name + ".tmp-%d" % os.getpid())
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=True, sort_keys=True)
    os.replace(str(tmp), str(path))
    return data


def state_dir() -> Path:
    """Own state directory (plans, manifests, reports, installed dua), mode 0o700.

    macOS/Linux ~/.corecleaner; Windows %LOCALAPPDATA%\\corecleaner; CORECLEANER_STATE_DIR overrides.
    The only place corecleaner may create or replace files besides an explicit archive destination.
    """
    return _private_dir(state_dir_path())


def state_dir_path() -> Path:
    """Where the state dir is (or would be), without creating it: read-only commands look, never make."""
    override = os.environ.get(STATE_ENV)
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "corecleaner"
    return Path.home() / ".corecleaner"


def state_subdir(name: str) -> Path:
    """`state_dir()/<name>` (e.g. "plans", "runs", "reports", "bin"), mode 0o700. Single component only."""
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        raise ValueError("state_subdir takes a single path component: " + repr(name))
    return _private_dir(state_dir() / name)


KEY_FILE = "mac.key"


def canonical_bytes(obj: Any) -> bytes:
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_json_default)
    return text.encode("utf-8", "surrogatepass")


def state_key() -> bytes:
    """32 random bytes in the state dir (mode 0600), created on first use.

    Plans and inventories are signed with it, so a file written by anything that never read the key
    (an agent steered by a file name, a script) is rejected. It is not a defence against a process
    that can read the state dir: the saved files and `~/.corecleaner/**` stay off limits for agents.
    """
    path = state_dir() / KEY_FILE
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError:
        fd = -1
    except OSError as exc:
        raise CorecleanerError(EXIT_ERROR, "cannot create the signing key: " + str(exc.strerror), path=str(path))
    if fd >= 0:
        try:
            os.write(fd, secrets.token_bytes(32))
            os.fsync(fd)
        finally:
            os.close(fd)
    try:
        st = os.lstat(str(path))
        if not stat.S_ISREG(st.st_mode) or (os.name == "posix" and (st.st_uid != os.geteuid() or st.st_mode & 0o077)):
            raise CorecleanerError(EXIT_ERROR, "signing key is not a private regular file; refusing", path=str(path))
        data = path.read_bytes()
    except OSError as exc:
        raise CorecleanerError(EXIT_ERROR, "cannot read the signing key: " + str(exc.strerror), path=str(path))
    if len(data) < 32:
        raise CorecleanerError(EXIT_ERROR, "signing key is truncated; delete it to start a new one", path=str(path))
    return data


def sign(obj: Any, purpose: str) -> str:
    """HMAC-SHA256 hex of the canonical JSON of `obj`, bound to `purpose` ("plan", "inventory")."""
    return hmac.new(state_key(), purpose.encode("ascii") + b"\0" + canonical_bytes(obj), hashlib.sha256).hexdigest()


def verify(obj: Any, mac: Any, purpose: str) -> bool:
    # compare_digest raises TypeError on a non-ASCII str: a hand-edited file must be a plain "no", not a crash
    return isinstance(mac, str) and mac.isascii() and hmac.compare_digest(mac, sign(obj, purpose))


_LSOF_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
_LSOF_BYTE = re.compile(r"\\x([0-9a-fA-F]{2})")


def unescape_lsof(text: str) -> str:
    """Undo lsof's `\\xNN` for bytes it cannot print in the current locale (LC_ALL=C, a bare sandbox).

    Without this a folder like `Criação` comes back as `Cria\\xc3\\xa7\\xc3\\xa3o`, never equals the real
    path, and a process working inside it goes unseen.
    """
    if "\\x" not in text:
        return text

    def repl(match: "re.Match[str]") -> str:
        raw = bytes(int(h, 16) for h in _LSOF_BYTE.findall(match.group(0)))
        return raw.decode("utf-8", "surrogateescape")

    return _LSOF_ESCAPES.sub(repl, text)
