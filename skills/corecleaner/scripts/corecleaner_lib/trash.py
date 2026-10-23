"""OS Trash, run manifest, undo. (T3; subcommands `trash`, `undo`)

The ONLY module that moves user data, and only to the OS Trash. Never os.remove / unlink /
shutil.rmtree / shutil.move on a user path; no permanent-delete fallback exists (SPEC trava 4).
tests/test_trash.py greps this file's AST for those calls. The one allowed unlink is
_drop_own_trashinfo: the Trash's own `info/<name>.trashinfo` bookkeeping file of an item undo just restored.

run(args) dispatches on args.cmd:
  "trash": args.plan (file), args.ids (list[str]), args.apply (bool, default False = dry-run)
  "undo":  args.run (run id)

trash flow (per id, in plan order), `_evaluate` then archive then manifest then Trash:
  1. plan.load_plan(args.plan) validates the hash (else exit 41); a plan older than
     plan.MAX_AGE_HOURS is refused with --apply (exit 42, "re-run inventory"; the dry run only
     adds `warnings`); ids must exist in the plan (else exit 2), never a free path, no --force.
  2. Re-check right before acting (42): exists, realpath == plan path, inode same, mtime not
     newer than the plan, not a symlink/junction, no control characters in the path.
  3. safety.is_protected (40); safety.is_cloud_or_placeholder (skipped, list only); live process
     (43: mtime < 1 h, or any process whose cwd is inside the path; claude/codex are named in the
     reason; Windows only has the mtime test); platform_info.trash_available (30).
     A per-item 40/42/43 denies that item only. The first code 30 or the first Trash failure stops
     the batch: the rest is "skipped" and run() raises with the partial result in error_details.
  4. Directory holding a .git (or action archive_then_trash): archive.needs_archive ->
     archive.archive_repo into ~/corecleaner-archive/<YYYYMMDD>/<id> before trashing. No space (44)
     skips the item; any other archive failure marks it failed. Never trashed without the archive.
     The archive folder has a cap (archive.ARCHIVE_CAP_BYTES, 20 GiB): archive.check_quota runs first,
     an archive that would pass it skips the item with code 44 and creates nothing. The result carries
     `archive_store` (size, cap, archives 90 days or older, a `prune_command` for the USER): archives
     are never deleted by this tool.
  5. write_manifest(intent), send_to_trash, write_manifest(done | fail).
Dry-run does steps 1-4 (needs_archive only reads) and reports ok/deny/skipped per id; it writes no
manifest and creates nothing. Result: {"run_id", "apply", "items": [{"id", "status": "ok" | "deny"
| "skipped" | "failed", "reason", "bytes", "dest", "display", "code"?}], "apparent_bytes", "trashed_bytes",
"not_ok", "note", "gain_note", "warnings"?}. `apparent_bytes` adds the per-path upper bounds of the "ok" rows (0 in
a dry run; `trashed_bytes` is the same number under its old name, kept for one release); `gain_note` is the plan's
GAIN_NOTE. `not_ok` counts the requested ids whose status is not "ok"; when it is above 0 corecleaner.py exits 46
(EXIT_PARTIAL) after printing the whole document (still "ok": true, every row present), in dry-run too.
--apply with stdout not a terminal adds the "no proof a person answered" warning, and
CORECLEANER_REQUIRE_TTY_APPLY=1 refuses it (exit 2) before the plan is read (common.apply_guard).

send_to_trash(path) -> dest
  macOS: /usr/bin/trash -v (dest parsed from `# Moved "src" to "dest"`; dest gets a time suffix
  on a name clash), else osascript Finder `delete` (dest = the POSIX path it returns).
  Linux: `gio trash`, else/then `trash-put`; dest computed from the freedesktop.org Trash spec
  (home Trash when on the same device, else $topdir/.Trash/$uid, else $topdir/.Trash-$uid) by
  reading the newest .trashinfo whose Path= matches.
  Windows (BETA, untested): PowerShell Microsoft.VisualBasic FileSystem DeleteFile/DeleteDirectory
  with SendToRecycleBin, then verify the item is gone and the Recycle Bin grew.
  No Trash tool -> CorecleanerError(EXIT_NO_TRASH). Before moving: absolute path, exists, not a
  symlink/junction, safety.is_protected, platform_info.trash_available.
  Moved but destination unknown -> DestinationUnknown (the item is in the Trash, undo is blind).

write_manifest(run_id, entry) -> Path
  Append one JSON line (ASCII-escaped, so undecodable names round-trip) to
  state_subdir("runs")/<run_id>.jsonl, mode 0o600, fsync. entry keys: ts, id, phase, src, bytes,
  dest, error (+ extras such as archive), sig. phase: intent | done | fail | undone. `sig` is an HMAC
  (common.sign, purpose "manifest", state key) over {"run": run_id, "rec": the line without sig}: a line
  written by anything that never read the key, edited, or copied from another run does not verify.

undo(run_id) -> dict
  Lines that fail the signature are ignored (reported in "failed", counted in "rejected_lines"). Per id,
  the LAST signed phase decides. "done" with a dest: move dest back to src with os.rename only (never
  copy+delete, never overwrite: a busy src is reported), only if dest is inside one of THIS user's Trash
  folders (_user_trash_roots: ~/.Trash, <mount>/.Trashes/<uid>, XDG Trash/files, <mount>/.Trash/<uid>/files,
  <mount>/.Trash-<uid>/files; not any folder that is merely named like one), the record carries the inode and
  device of what was moved and what sits at dest is that object, src is not protected and src's folder
  exists. When only the device number differs (an external disk replugged comes up under a new one), the
  object must match on inode, size and mtime_ns instead; the restored row then carries a "note" and a refusal
  says "device renumbered". On a freedesktop.org Trash (Linux) the restored item's own
  `info/<name>.trashinfo` is removed so no orphan stays (only a plain `[Trash Info]` file naming src).
  Then phase "undone".
  Result: {"run_id", "restored": [{"id", "src", "note"?}], "failed": [{"id", "reason"}],
  "skipped": [{"id", "reason"}], "rejected_lines"}.
"""

from __future__ import annotations

import base64
import errno
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import unicodedata
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import unquote

from corecleaner_lib import archive, inventory, platform_info, safety
from corecleaner_lib import plan as plan_mod
from corecleaner_lib.common import (
    EXIT_DENYLISTED,
    EXIT_ERROR,
    EXIT_LIVE_PROCESS,
    EXIT_NO_SPACE_FOR_ARCHIVE,
    EXIT_NO_TRASH,
    EXIT_STATE_CHANGED,
    EXIT_USAGE,
    CorecleanerError,
    apply_guard,
    file_stamp,
    now_iso,
    sign,
    state_subdir,
    unescape_lsof,
    verify,
)

Runner = Callable[..., Tuple[int, str, str]]

NOTE_NOT_EMPTIED = "Trash not emptied: free space unchanged until you empty it"
WINDOWS_BETA = "[BETA, untested] "
LIVE_WINDOW_SECONDS = 3600
MTIME_TOLERANCE = 1e-3
_MAC_TRASH = "/usr/bin/trash"
_MAC_OSASCRIPT = "/usr/bin/osascript"
_REPARSE_POINT = 0x400
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")
_PHASES = ("intent", "done", "fail", "undone")
_MANIFEST_KEYS = ("ts", "id", "phase", "src", "bytes", "dest", "error")
NESTED_REPO_DEPTH = 6
WIN_PATH_LIMIT = 240  # the Shell deletes for good what it cannot address in the Recycle Bin (MAX_PATH is 260)
WIN_DEFAULT_BIN_SHARE = 0.05  # of the volume, when the Recycle Bin size is not in the registry
MAX_FILENAME_BYTES = 255
MAX_REJECTED_ROWS = 20  # undo lists at most this many unsigned or edited manifest lines; rejected_lines has the count


class TrashFailure(CorecleanerError):
    """The Trash tool failed; the item was NOT moved (or its move could not be confirmed)."""

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(EXIT_ERROR, message, **details)


class DestinationUnknown(CorecleanerError):
    """The item left its place for the Trash but the Trash path is unknown: undo cannot find it."""

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(EXIT_ERROR, message, **details)


# ---------------------------------------------------------------- helpers


def _clean(text: Any, limit: int = 300) -> str:
    s = "".join(" " if safety.is_unsafe_char(c) else c for c in str(text))
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: limit - 3] + "..."


def _has_control(text: str) -> bool:
    return plan_mod.has_control(text)  # one set with plan and sanitize_name


def _is_link_or_junction(st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def _run_tool(argv: Sequence[str], env: Optional[dict] = None, timeout: float = 600) -> Tuple[int, str, str]:
    """Run one external tool without a shell; returns (returncode, stdout, stderr)."""
    name = os.path.basename(argv[0])
    try:
        proc = subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        raise TrashFailure("%s timed out after %ds" % (name, timeout))
    except OSError as exc:
        raise TrashFailure("cannot run %s: %s" % (name, exc.strerror or exc))
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _preflight(path: str) -> None:
    """Refusals that hold for every OS, checked right before a move."""
    if not isinstance(path, str) or not path or not os.path.isabs(path):
        raise CorecleanerError(EXIT_USAGE, "send_to_trash needs an absolute path")
    where = _clean(path, 200)
    try:
        st = os.lstat(path)
    except OSError:
        raise CorecleanerError(EXIT_STATE_CHANGED, "item no longer exists", path=where)
    if _is_link_or_junction(st):
        raise CorecleanerError(EXIT_STATE_CHANGED, "refusing a symlink or junction", path=where)
    if _has_control(path):
        raise CorecleanerError(EXIT_STATE_CHANGED, "path contains control characters", path=where)
    protected, why = safety.is_protected(path)
    if protected:
        raise CorecleanerError(EXIT_DENYLISTED, "protected path: " + _clean(why), path=where)
    available, info = platform_info.trash_available(path)
    if not available:
        raise CorecleanerError(EXIT_NO_TRASH, "no Trash for this volume: " + _clean(info), path=where)


def _gone_or_fail(path: str, tool: str) -> None:
    if os.path.lexists(path):
        raise TrashFailure("%s reported success but the item is still in place" % tool)


# ---------------------------------------------------------------- macOS


def _parse_mac_moved(stdout: str, src: str) -> Optional[str]:
    """Destination from `# Moved "src" to "dest"` (also the older unquoted `Moved src to dest`)."""
    base = os.path.basename(src)
    for line in stdout.splitlines():
        m = re.match(r"^#?\s*Moved\s+(.*)$", line.strip())
        if not m:
            continue
        rest = m.group(1)
        if len(rest) >= 2 and rest.startswith('"') and rest.endswith('"'):
            inner, marker = rest[1:-1], '" to "'
        else:
            inner, marker = rest, " to "
        pairs: List[Tuple[str, str]] = []
        start = inner.find(marker)
        while start >= 0:
            pairs.append((inner[:start], inner[start + len(marker):]))
            start = inner.find(marker, start + 1)
        # A name containing the marker makes the split ambiguous: prefer splits whose source part
        # ends with the real file name, then one that exists on disk.
        pool = [d for s, d in pairs if s.endswith(base)] or [d for _, d in pairs]
        pool = [os.path.expanduser(d) for d in pool]
        for d in pool:
            if os.path.lexists(d):
                return d
        if len(pool) == 1:
            return pool[0]
    return None


def _trash_macos(path: str, run: Runner, which: Callable[[str], Optional[str]]) -> str:
    if which(_MAC_TRASH):
        rc, out, err = run([_MAC_TRASH, "-s", "-v", path])  # -s: a refusal exits non-zero instead of 0
        if rc != 0:
            raise TrashFailure("trash exited %d: %s" % (rc, _clean(err or out)))
        if os.path.lexists(path):
            raise TrashFailure("trash reported success but the item is still in place: " + _clean(err or out or "no output", 200))
        dest = _parse_mac_moved(out, path)
    elif which(_MAC_OSASCRIPT):
        script = [
            "on run argv",
            "set p to POSIX file (item 1 of argv)",
            'tell application "Finder"',
            "set r to delete p",
            "end tell",
            "return POSIX path of (r as alias)",
            "end run",
        ]
        argv = [_MAC_OSASCRIPT]
        for line in script:
            argv += ["-e", line]
        rc, out, err = run(argv + [path], timeout=180)
        if rc != 0:
            raise TrashFailure("Finder delete failed (%d): %s" % (rc, _clean(err or out)))
        _gone_or_fail(path, "Finder")
        dest = os.path.expanduser(out.strip()) if out.strip() else None
        if dest is not None and not os.path.isabs(dest):
            dest = None
    else:
        raise CorecleanerError(EXIT_NO_TRASH, "no Trash tool on macOS (need /usr/bin/trash or osascript)")
    if not dest:
        raise DestinationUnknown("moved to the Trash but its location was not reported")
    return dest


# ---------------------------------------------------------------- Linux (freedesktop.org Trash spec)


def _xdg_trash_home() -> str:
    base = os.environ.get("XDG_DATA_HOME")
    if not base or not os.path.isabs(base):
        base = os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "Trash")


def _device_of(path: str) -> Optional[int]:
    cur = path
    while True:
        try:
            return os.stat(cur).st_dev
        except OSError:
            parent = os.path.dirname(cur)
            if parent == cur:
                return None
            cur = parent


def _same_device(a: str, b: str) -> bool:
    dev_a, dev_b = _device_of(a), _device_of(b)
    return dev_a is not None and dev_a == dev_b


def _mount_point(path: str) -> str:
    cur = os.path.dirname(os.path.realpath(path))
    while not os.path.ismount(cur):
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return cur


def _linux_trash_dirs(path: str) -> List[Tuple[str, Optional[str]]]:
    """Candidate Trash directories for `path`, most likely first, with their topdir (None = home)."""
    dirs: List[Tuple[str, Optional[str]]] = []
    home = _xdg_trash_home()
    if _same_device(path, home):
        dirs.append((home, None))
    top = _mount_point(path)
    uid = os.getuid()
    shared = os.path.join(top, ".Trash")
    try:
        st = os.lstat(shared)
        if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and st.st_mode & stat.S_ISVTX:
            dirs.append((os.path.join(shared, str(uid)), top))
    except OSError:
        pass
    dirs.append((os.path.join(top, ".Trash-%d" % uid), top))
    return dirs


def _canon(p: str) -> str:
    return os.path.join(os.path.realpath(os.path.dirname(p)), os.path.basename(p))


def _trashinfo_path(info_file: str) -> Optional[str]:
    try:
        with open(info_file, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read(65536)
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("Path="):
            return unquote(line[5:])
    return None


def _find_linux_dest(path: str, started: float, dirs: List[Tuple[str, Optional[str]]]) -> Optional[str]:
    wanted = {path, _canon(path)}
    fresh: List[str] = []
    for trash_dir, top in dirs:
        info_dir = os.path.join(trash_dir, "info")
        try:
            names = [n for n in os.listdir(info_dir) if n.endswith(".trashinfo")]
        except OSError:
            continue
        stamped = []
        for n in names:
            try:
                stamped.append((os.lstat(os.path.join(info_dir, n)).st_mtime, n))
            except OSError:
                continue
        stamped.sort(reverse=True)
        for mtime, n in stamped[:200]:
            dest = os.path.join(trash_dir, "files", n[: -len(".trashinfo")])
            if not os.path.lexists(dest):
                continue
            recorded = _trashinfo_path(os.path.join(info_dir, n))
            if recorded is not None and not os.path.isabs(recorded) and top:
                recorded = os.path.join(top, recorded)  # non-home Trash stores Path relative to topdir
            if recorded is not None and os.path.isabs(recorded) and (
                recorded in wanted or _canon(recorded) in wanted
            ):
                return dest
            if mtime >= started - 2:
                fresh.append(dest)
    return fresh[0] if len(fresh) == 1 else None


def _trash_linux(path: str, run: Runner, which: Callable[[str], Optional[str]]) -> str:
    tools = []
    if which("gio"):
        tools.append(("gio", ["gio", "trash", "--", path]))
    if which("trash-put"):
        tools.append(("trash-put", ["trash-put", "--", path]))
    if not tools:
        raise CorecleanerError(
            EXIT_NO_TRASH, "no Trash tool on Linux: install glib (gio) or trash-cli; corecleaner never deletes instead"
        )
    dirs = _linux_trash_dirs(path)
    started = time.time()
    failures: List[str] = []
    for name, argv in tools:
        rc, out, err = run(argv)
        if rc == 0 and not os.path.lexists(path):
            dest = _find_linux_dest(path, started, dirs)
            if not dest:
                raise DestinationUnknown("%s moved the item but no matching .trashinfo was found" % name)
            return dest
        failures.append("%s: %s" % (name, _clean(err or out or ("exit %d" % rc), 160)))
    raise TrashFailure("Trash failed (" + "; ".join(failures) + ")")


# ---------------------------------------------------------------- Windows (BETA)

_WIN_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName Microsoft.VisualBasic
$p = $env:CORECLEANER_TARGET
function Get-BinItems {
  $ns = (New-Object -ComObject Shell.Application).Namespace(10)
  @($ns.Items() | ForEach-Object {
    [pscustomobject]@{ Name = [string]$_.Name; From = [string]$ns.GetDetailsOf($_, 1); Path = [string]$_.Path }
  })
}
$leaf = [System.IO.Path]::GetFileName($p)
$stem = [System.IO.Path]::GetFileNameWithoutExtension($p)
$parent = [System.IO.Path]::GetDirectoryName($p)
$item = Get-Item -LiteralPath $p -Force
if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'reparse point refused' }
$before = Get-BinItems
if ($item.PSIsContainer) {
  [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($p, 'OnlyErrorDialogs', 'SendToRecycleBin')
} else {
  [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($p, 'OnlyErrorDialogs', 'SendToRecycleBin')
}
$after = Get-BinItems
$known = @{}
foreach ($b in $before) { $known[$b.Path] = $true }
$fresh = @($after | Where-Object { -not $known.ContainsKey($_.Path) -and $_.From -eq $parent -and ($_.Name -eq $leaf -or $_.Name -eq $stem) })
$dest = ''
if ($fresh.Count -ge 1) { $dest = $fresh[0].Path }
[pscustomobject]@{ before = $before.Count; after = $after.Count; exists_after = [bool](Test-Path -LiteralPath $p); dest = $dest } | ConvertTo-Json -Compress
"""


def _bin_capacity_bytes(path: str) -> int:
    """Smallest Recycle Bin size the user configured (registry, MB), else a share of the volume holding `path`."""
    smallest = None
    try:
        import winreg  # type: ignore[import-not-found]

        key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as root:
            for i in range(winreg.QueryInfoKey(root)[0]):
                try:
                    with winreg.OpenKey(root, winreg.EnumKey(root, i)) as sub:
                        mb = int(winreg.QueryValueEx(sub, "MaxCapacity")[0])
                except (OSError, ValueError):
                    continue
                if mb > 0 and (smallest is None or mb < smallest):
                    smallest = mb
    except (ImportError, OSError):
        pass
    if smallest is not None:
        return smallest * 1024 * 1024
    return int(shutil.disk_usage(path).total * WIN_DEFAULT_BIN_SHARE)


def _windows_recycle_risk(path: str, capacity: Optional[Callable[[str], int]] = None) -> Optional[str]:
    """Why the Shell would delete `path` FOR GOOD instead of keeping it in the Recycle Bin, else None. (BETA)

    FileSystem.DeleteDirectory/DeleteFile with OnlyErrorDialogs sets FOF_NOCONFIRMATION and never
    FOF_WANTNUKEWARNING, so an item bigger than the Recycle Bin, or holding a path the Bin cannot
    address, is destroyed without a question. Nothing can be checked afterwards: refuse beforehand.
    """
    total = 0
    longest = len(path)
    stack = [path]
    seen = 0
    try:
        first = os.lstat(path)
        total = first.st_size
        if not stat.S_ISDIR(first.st_mode) or _is_link_or_junction(first):
            stack = []
        while stack:
            with os.scandir(stack.pop()) as it:
                for entry in it:
                    seen += 1
                    if seen > plan_mod.WALK_CAP:
                        return "too many entries to prove it fits the Recycle Bin"
                    longest = max(longest, len(entry.path))
                    st = entry.stat(follow_symlinks=False)
                    total += st.st_size
                    if stat.S_ISDIR(st.st_mode) and not _is_link_or_junction(st):
                        stack.append(entry.path)
    except OSError as exc:
        return "cannot measure it for the Recycle Bin (%s)" % _clean(exc.strerror or type(exc).__name__, 60)
    if longest >= WIN_PATH_LIMIT:
        return "holds a path of %d characters; the Recycle Bin cannot keep it and Windows would delete it for good" % longest
    try:
        limit = (capacity or _bin_capacity_bytes)(path)
    except OSError:
        return "cannot read the Recycle Bin size"
    if total >= limit:
        return "%d bytes do not fit the Recycle Bin (%d); Windows would delete it for good" % (total, limit)
    return None


def _trash_windows(path: str, run: Runner, which: Callable[[str], Optional[str]]) -> str:
    exe = which("powershell.exe") or which("powershell") or which("pwsh")
    if not exe:
        raise CorecleanerError(EXIT_NO_TRASH, WINDOWS_BETA + "PowerShell not found; cannot reach the Recycle Bin")
    risk = _windows_recycle_risk(path)
    if risk:
        raise TrashFailure(WINDOWS_BETA + risk)
    encoded = base64.b64encode(_WIN_SCRIPT.encode("utf-16-le")).decode("ascii")
    argv = [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]
    env = dict(os.environ)
    env["CORECLEANER_TARGET"] = path  # the path travels in the environment, never inside the script text
    rc, out, err = run(argv, env=env)
    if rc != 0:
        if not os.path.lexists(path):
            raise DestinationUnknown(
                WINDOWS_BETA + "PowerShell exited %d after the item left its place; check the Recycle Bin by hand" % rc
            )
        raise TrashFailure(WINDOWS_BETA + "PowerShell exited %d: %s" % (rc, _clean(err or out)))
    report: Dict[str, Any] = {}
    for line in reversed(out.strip().splitlines()):
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            report = parsed
            break
    before, after = report.get("before"), report.get("after")
    grew = isinstance(before, int) and isinstance(after, int) and after > before
    if os.path.lexists(path) or report.get("exists_after") is not False:
        raise TrashFailure(WINDOWS_BETA + "the item is still in place after SendToRecycleBin")
    if not grew:
        raise TrashFailure(
            WINDOWS_BETA + "item gone but the Recycle Bin did not grow: possible permanent deletion, batch stopped",
            permanent_deletion_suspected=True,
        )
    dest = report.get("dest")
    if not isinstance(dest, str) or not dest:
        raise DestinationUnknown(WINDOWS_BETA + "item is in the Recycle Bin but its location was not reported")
    return dest


# ---------------------------------------------------------------- public: send_to_trash


def send_to_trash(
    path: str, runner: Optional[Runner] = None, which: Optional[Callable[[str], Optional[str]]] = None
) -> str:
    """Move `path` to the OS Trash and return its destination there. `runner`/`which` are test seams."""
    run = runner or _run_tool
    find = which or shutil.which
    _preflight(path)
    kind = platform_info.os_kind()
    if kind == "macos":
        return _trash_macos(path, run, find)
    if kind == "linux":
        return _trash_linux(path, run, find)
    if kind == "windows":
        return _trash_windows(path, run, find)
    raise CorecleanerError(EXIT_NO_TRASH, "unsupported OS for the Trash: " + _clean(kind))


# ---------------------------------------------------------------- manifest


def _manifest_path(run_id: str) -> Path:
    if not isinstance(run_id, str) or not _RUN_ID_RE.match(run_id):
        raise CorecleanerError(EXIT_USAGE, "invalid run id", run=_clean(run_id, 60))
    return state_subdir("runs") / (run_id + ".jsonl")


def write_manifest(run_id: str, entry: dict) -> Path:
    phase = entry.get("phase")
    if phase not in _PHASES:
        raise ValueError("manifest phase must be one of %s, got %r" % (_PHASES, phase))
    if not entry.get("id") or not isinstance(entry.get("src"), str):
        raise ValueError("manifest entry needs id and src")
    record: Dict[str, Any] = {k: entry.get(k) for k in _MANIFEST_KEYS}
    record["ts"] = entry.get("ts") or now_iso()
    for key, value in entry.items():
        if key not in record and key != "sig":
            record[key] = value
    signed = dict(record, sig=_manifest_sig(run_id, record))
    line = (json.dumps(signed, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
    target = _manifest_path(run_id)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(str(target), flags, 0o600)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)
    return target


def _manifest_sig(run_id: str, record: dict) -> str:
    """HMAC of one manifest line, bound to its run id so a line cannot be moved to another run."""
    return sign({"run": run_id, "rec": record}, "manifest")


def _read_manifest_checked(run_id: str) -> Tuple[List[dict], List[str]]:
    """(records whose signature holds, ids of lines that parse but fail it). Unparseable lines are ignored."""
    target = _manifest_path(run_id)
    try:
        text = target.read_text(encoding="ascii", errors="replace")
    except OSError:
        raise CorecleanerError(EXIT_ERROR, "no manifest for this run id", run=run_id)
    records: List[dict] = []
    rejected: List[str] = []
    for line in text.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not (isinstance(rec, dict) and rec.get("phase") in _PHASES and rec.get("id")):
            continue
        mac = rec.pop("sig", None)
        if not verify({"run": run_id, "rec": rec}, mac, "manifest"):
            rejected.append(_clean(rec.get("id"), 40))
            continue
        records.append(rec)
    return records, rejected


def _read_manifest(run_id: str) -> List[dict]:
    return _read_manifest_checked(run_id)[0]


# ---------------------------------------------------------------- undo


def _user_trash_roots(near: str) -> List[str]:
    """Folders where THIS user's Trash keeps items; `near` picks the volume for the per-volume ones.

    macOS: ~/.Trash and <mount>/.Trashes/<uid>. Linux (freedesktop.org): $XDG_DATA_HOME/Trash/files,
    <mount>/.Trash/<uid>/files, <mount>/.Trash-<uid>/files. Windows (BETA, no SID check): the S-1-* folders
    of <drive>\\$Recycle.Bin. A folder merely named .Trash somewhere else is not on the list.
    """
    kind = platform_info.os_kind()
    roots: List[str] = []
    uid = os.getuid() if hasattr(os, "getuid") else None
    if kind == "macos":
        roots.append(os.path.join(os.path.expanduser("~"), ".Trash"))
        if uid is not None:
            roots.append(os.path.join(_mount_point(near), ".Trashes", str(uid)))
    elif kind == "linux":
        roots.append(os.path.join(_xdg_trash_home(), "files"))
        if uid is not None:
            top = _mount_point(near)
            roots.append(os.path.join(top, ".Trash", str(uid), "files"))
            roots.append(os.path.join(top, ".Trash-%d" % uid, "files"))
    elif kind == "windows":
        bin_dir = os.path.join(os.path.splitdrive(near)[0] + os.sep, "$Recycle.Bin")
        try:
            roots += [os.path.join(bin_dir, n) for n in os.listdir(bin_dir) if n.upper().startswith("S-1-")]
        except OSError:
            pass
    return roots


def _is_trash_location(dest: str) -> bool:
    """True only when `dest` sits (after resolving every link in its folder) inside one of this user's Trash folders."""
    if not isinstance(dest, str) or not os.path.isabs(dest) or ".." in Path(dest).parts or not os.path.basename(dest):
        return False
    fold = str.casefold if platform_info.os_kind() in ("macos", "windows") else str  # those file systems ignore case
    real = os.path.join(os.path.realpath(os.path.dirname(dest)), os.path.basename(dest))
    for root in _user_trash_roots(dest):
        if os.path.islink(root):
            continue  # a Trash folder that is a link could lead anywhere
        prefix = os.path.realpath(root).rstrip(os.sep) + os.sep
        if fold(real).startswith(fold(prefix)):
            return True
    return False


_RENAME_EXCL = 0x4  # macOS renamex_np flag
_RENAME_NOREPLACE = 1  # Linux renameat2 flag


def _rename_noreplace(src: str, dst: str) -> None:
    """Rename that fails with FileExistsError when `dst` exists, with no gap between the check and the move.

    macOS renamex_np(RENAME_EXCL), Linux renameat2(RENAME_NOREPLACE); where the kernel or filesystem
    lacks it, a lexists check then os.rename (POSIX rename would overwrite a file that appeared in
    between). Windows os.rename already refuses an existing target.
    """
    flavor = sys.platform
    if flavor == "darwin" or flavor.startswith("linux"):
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        a, b = os.fsencode(src), os.fsencode(dst)
        rc = -1
        if flavor == "darwin" and hasattr(libc, "renamex_np"):
            rc = libc.renamex_np(a, b, _RENAME_EXCL)
        elif hasattr(libc, "renameat2"):
            rc = libc.renameat2(-100, a, -100, b, _RENAME_NOREPLACE)  # AT_FDCWD
        if rc == 0:
            return
        err = ctypes.get_errno()
        if rc == -1 and err in (errno.EEXIST, errno.ENOTEMPTY):
            raise FileExistsError(err, os.strerror(err), dst)
        if rc == -1 and err not in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, 0):
            raise OSError(err, os.strerror(err), src)
    if os.path.lexists(dst):
        raise FileExistsError(errno.EEXIST, "target exists", dst)
    os.rename(src, dst)


def _is_number(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


NOTE_RENUMBERED = "device renumbered since the run: matched by inode, size and mtime instead of the device number"
NOTE_INFO_KEPT = "left the Trash's .trashinfo file in place: "


def _read_trashinfo_path(info_file: str) -> Optional[str]:
    """The decoded `Path=` of a freedesktop.org .trashinfo, only when it opens with `[Trash Info]`."""
    try:
        with open(info_file, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read(65536).splitlines()
    except OSError:
        return None
    if not lines or lines[0].strip() != "[Trash Info]":
        return None
    for line in lines[1:]:
        if line.startswith("Path="):
            return unquote(line[5:])
    return None


def _drop_own_trashinfo(dest: str, src: str) -> Optional[str]:
    """Remove the `<Trash>/info/<name>.trashinfo` that described `dest`, now that `dest` went back to `src`.

    The only deletion in this module, and only of the Trash's own bookkeeping file for the very item just
    restored, never user data: `dest` must have sat in a `files` folder (freedesktop.org layout; macOS and
    Windows have no such file), the file must be a small regular file (not a link) that opens with
    `[Trash Info]`, and its `Path=` must name `src`. Anything else is left alone and the returned text says
    why; None means it was removed or there was nothing to remove.
    """
    files_dir = os.path.dirname(dest)
    if os.path.basename(files_dir) != "files":
        return None
    trash_dir = os.path.dirname(files_dir)
    info = os.path.join(trash_dir, "info", os.path.basename(dest) + ".trashinfo")
    try:
        st = os.lstat(info)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > 65536:
        return NOTE_INFO_KEPT + "it is not a plain small file"
    recorded = _read_trashinfo_path(info)
    if recorded is None:
        return NOTE_INFO_KEPT + "it is not a readable [Trash Info] file"
    if not os.path.isabs(recorded):  # a per-volume Trash stores Path relative to the volume's top directory
        tops = {os.path.dirname(trash_dir), os.path.dirname(os.path.dirname(trash_dir)), _mount_point(src)}
        candidates = {os.path.join(top, recorded) for top in tops}
    else:
        candidates = {recorded}
    wanted = {src, _canon(src)}
    if not any(c in wanted or _canon(c) in wanted for c in candidates):
        return NOTE_INFO_KEPT + "it describes another original path"
    try:
        os.unlink(info)
    except OSError as exc:
        return NOTE_INFO_KEPT + "it could not be removed (%s)" % _clean(exc.strerror or exc, 60)
    return None


def _identity_problem(rec: dict, dest_st: os.stat_result) -> Tuple[Optional[str], Optional[str]]:
    """(why what sits at the recorded Trash location is not the object this run moved, note); both None = same.

    The Trash reuses names: after it was emptied, another folder called `out` may sit where this run's
    `out` was. Only the very object the run moved (same inode and device, same size for a file) goes back,
    and a record that carries no inode and device cannot prove it, so it is refused.
    A device number is not stable: an external disk that is unplugged and plugged back can come up under a
    new one, and every inode on it is then "on another device". When only the device differs, the object must
    still agree on inode, size and its own mtime in nanoseconds (the move does not touch it); the reason says
    "device renumbered" either way.
    """
    if not _is_number(rec.get("ino")) or not _is_number(rec.get("dev")):
        return "the manifest has no inode and device for this item, so it cannot be proven to be the same one; refusing", None
    same_size = rec.get("size") is None or dest_st.st_size == rec["size"]
    if dest_st.st_dev == rec["dev"]:
        # ext4 and most Linux filesystems hand a freed inode number to the next new file at once, so on Linux an
        # inode match alone can be another folder: its own mtime must match too. APFS never reuses inode numbers,
        # and on macOS Finder rewrites a folder's mtime when it is merely browsed in the Trash, so there it is skipped.
        reused = (platform_info.os_kind() != "macos" and _is_number(rec.get("mtime_ns"))
                  and dest_st.st_mtime_ns != rec["mtime_ns"])
        if dest_st.st_ino != rec["ino"] or not same_size or reused:
            return "what is at the recorded Trash location is not what this run moved; refusing", None
        return None, None
    if not _is_number(rec.get("mtime_ns")):
        return "device renumbered since the run, and the manifest has no mtime to compare; refusing", None
    if dest_st.st_ino != rec["ino"] or not same_size or dest_st.st_mtime_ns != rec["mtime_ns"]:
        return "device renumbered since the run, and the inode, size and mtime do not all match what this run moved; refusing", None
    return None, NOTE_RENUMBERED


def _restore_one(rec: dict) -> Tuple[Optional[str], Optional[str]]:
    """Move one 'done' entry back. Returns (failure reason, None), or (None, note or None) when restored."""
    src, dest = rec.get("src"), rec.get("dest")
    if not isinstance(src, str) or not os.path.isabs(src):
        return "manifest has no usable original path", None
    if not dest:
        return "destination in the Trash was not recorded; look in the Trash by hand", None
    if not _is_trash_location(dest):
        return "recorded destination is not inside this user's Trash folder; refusing", None
    try:
        dest_st = os.lstat(dest)
    except OSError:
        return "no longer in the Trash (emptied, or restored by hand)", None
    if _is_link_or_junction(dest_st):
        return "item in the Trash is a symlink; refusing", None
    wrong, note = _identity_problem(rec, dest_st)
    if wrong:
        return wrong, None
    if os.path.lexists(src):
        return "original location is occupied; not overwriting", None
    if not os.path.isdir(os.path.dirname(src)):
        return "original folder no longer exists", None
    protected, why = safety.is_protected(src)
    if protected:
        return "original location is protected: " + _clean(why), None
    try:
        _rename_noreplace(dest, src)  # same-volume rename only: no copy+delete fallback exists
    except FileExistsError:
        return "original location is occupied; not overwriting", None
    except OSError as exc:
        return "move back failed: " + _clean(exc.strerror or exc, 120), None
    kept = _drop_own_trashinfo(dest, src)
    return None, "; ".join(n for n in (note, kept) if n) or None


def undo(run_id: str) -> dict:
    last: Dict[str, dict] = {}
    records, rejected = _read_manifest_checked(run_id)
    for rec in records:
        last[str(rec["id"])] = rec
    restored: List[dict] = []
    failed: List[dict] = []
    skipped: List[dict] = []
    for bad_id in rejected[:MAX_REJECTED_ROWS]:
        failed.append({"id": bad_id, "reason": "a manifest line failed its signature (edited, or written before lines were signed); ignored"})
    for item_id, rec in last.items():
        phase = rec["phase"]
        if phase == "undone":
            skipped.append({"id": item_id, "reason": "already restored"})
        elif phase == "fail":
            skipped.append({"id": item_id, "reason": "the move had failed; nothing to restore"})
        elif phase == "intent":
            failed.append({"id": item_id, "reason": "no completion record (run interrupted); check the Trash by hand"})
        else:
            reason, note = _restore_one(rec)
            if reason is None:
                row = {"id": item_id, "src": rec["src"]}
                if note:
                    row["note"] = note
                restored.append(row)
                write_manifest(
                    run_id,
                    {"id": item_id, "phase": "undone", "src": rec["src"], "bytes": rec.get("bytes"), "dest": rec.get("dest")},
                )
            else:
                failed.append({"id": item_id, "reason": reason})
    return {"run_id": run_id, "restored": restored, "failed": failed, "skipped": skipped, "rejected_lines": len(rejected)}


# ---------------------------------------------------------------- trash command


def _recheck(item: dict) -> Optional[str]:
    path = item.get("path")
    if not isinstance(path, str) or not os.path.isabs(path):
        return "plan item has no absolute path"
    if _has_control(path):
        return "path contains control characters"
    try:
        st = os.lstat(path)
    except OSError:
        return "no longer exists"
    if _is_link_or_junction(st):
        return "is now a symlink or junction"
    if os.path.normcase(os.path.realpath(path)) != os.path.normcase(path):
        return "path now resolves elsewhere (a parent changed)"
    inode = item.get("inode")
    if isinstance(inode, int) and inode and st.st_ino != inode:
        return "inode changed since the plan"
    mtime = item.get("mtime")
    if isinstance(mtime, (int, float)) and st.st_mtime > mtime + MTIME_TOLERANCE:
        return "modified since the plan"
    return None


_cwd_cache: Dict[str, Any] = {"at": 0.0, "procs": []}


def _lsof_cwds(run: Runner) -> List[Tuple[str, str]]:
    rc, out, _ = run(["lsof", "-w", "-n", "-d", "cwd", "-Fpcn"])
    if rc not in (0, 1) or not out:
        raise TrashFailure("lsof gave no usable answer")
    procs: List[Tuple[str, str]] = []
    cmd = pid = ""
    for line in out.splitlines():
        tag, value = line[:1], line[1:]
        if tag == "p":
            pid, cmd = value, ""
        elif tag == "c":
            cmd = value
        elif tag == "n":
            procs.append(("%s (pid %s)" % (_clean(cmd, 40), pid), unescape_lsof(value)))
    return procs


def _proc_cwds() -> List[Tuple[str, str]]:
    procs: List[Tuple[str, str]] = []
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                procs.append(("pid " + pid, os.readlink("/proc/%s/cwd" % pid)))
            except OSError:
                continue
    return procs


def _project_of(item: dict) -> Optional[inventory.Project]:
    """The project of a node_modules (E), a scratch unit (D) or a cache (F): same rule as the inventory's."""
    return inventory.project_of(str(item.get("category", "")), str(item.get("path", "")),
                                os.path.realpath(os.path.expanduser("~")))


def _live_reason(path: str, runner: Optional[Runner] = None, newest: float = 0.0,
                 project: Optional[inventory.Project] = None) -> Optional[str]:
    """Why `path` looks like live state, or None. Fails closed where it can look and cannot see.

    `newest` is the newest mtime found inside the tree: a directory's own mtime does not move when a
    file deep inside is written. `project` (inventory.project_of) adds the processes that work in the project
    the path belongs to, not only inside the path: `bun run dev` sits next to node_modules, never in it.
    """
    try:
        age = time.time() - max(os.lstat(path).st_mtime, newest)
    except OSError:
        return None
    if age < LIVE_WINDOW_SECONDS:
        return "modified less than 1 hour ago"
    kind = platform_info.os_kind()
    if kind == "windows":
        return None  # no cwd listing without extra tooling; only the mtime test applies (BETA)
    try:
        if kind == "linux" and os.path.isdir("/proc"):
            procs = _proc_cwds()
        elif runner is None and time.monotonic() - _cwd_cache["at"] < 5:
            procs = _cwd_cache["procs"]  # one lsof per few seconds, not one per item
        else:
            procs = _lsof_cwds(runner or _run_tool)
            if runner is None:
                _cwd_cache.update(at=time.monotonic(), procs=procs)
    except (TrashFailure, OSError) as exc:
        return "cannot verify running processes (" + _clean(exc, 80) + "); treated as live"
    path = unicodedata.normalize("NFC", path)  # macOS keeps names as created (NFD or NFC); compare one form
    prefix = path.rstrip(os.sep) + os.sep
    for who, cwd in procs:
        cwd = unicodedata.normalize("NFC", cwd)
        if cwd == path or cwd.startswith(prefix):
            tag = " (coding agent)" if re.search(r"claude|codex", who, re.I) else ""
            return "process %s has its working directory inside%s" % (who, tag)
    if project:
        where = (project[0], unicodedata.normalize("NFC", project[1]))
        for who, cwd in procs:
            if inventory.in_project(where, unicodedata.normalize("NFC", cwd)):
                return "a process works in the project (%s)" % who
    return None


def _looks_like_repo(path: str) -> bool:
    return os.path.isdir(path) and os.path.lexists(os.path.join(path, ".git"))


def _keeper_problem(item: dict) -> Optional[str]:
    """A duplicate may go only while the copy it duplicates is still there, byte for byte as planned."""
    keeper = item.get("keeper")
    if keeper is None:
        return None
    try:
        st = os.lstat(keeper["path"])
    except (OSError, KeyError, TypeError):
        return "the copy it duplicates is gone"
    if (
        not stat.S_ISREG(st.st_mode)
        or st.st_ino != keeper.get("inode")
        or st.st_size != keeper.get("size")
        or abs(st.st_mtime - float(keeper.get("mtime", 0))) > MTIME_TOLERANCE
    ):
        return "the copy it duplicates changed since the plan"
    return None


def _evaluate(item: dict) -> Optional[Tuple[str, Optional[int], str]]:
    """First reason this item must not be trashed now: (status, code, reason), or None."""
    action = item.get("action")
    if action == "tool_command":
        return ("skipped", None, "cleaned by the tool's own command: " + _clean(item.get("tool_command") or "", 120))
    if item.get("group") == 3 or action not in ("trash", "archive_then_trash") or item.get("deny"):
        return ("deny", EXIT_DENYLISTED, _clean(item.get("deny") or "list only, not trashable"))
    why = _recheck(item)
    if why:
        return ("deny", EXIT_STATE_CHANGED, why)
    try:
        checked = plan_mod.recheck_item(item)  # whole-tree mtime check (SPEC trava 3)
    except CorecleanerError as exc:
        return ("deny", exc.code, exc.message)
    if checked["partial"]:
        # A tree that was not read to the end can hide a file written a minute ago: idle is not proven.
        return ("deny", EXIT_LIVE_PROCESS, "could not read the whole tree (too large or unreadable): cannot prove it idle")
    newest = checked["newest_mtime"]
    path = item["path"]
    protected, rule = safety.is_protected(path)
    if protected:
        return ("deny", EXIT_DENYLISTED, "protected: " + _clean(rule))
    inside = plan_mod.protected_inside_reason(str(item.get("category", "")), path)
    if inside:
        return ("deny", EXIT_DENYLISTED, inside)
    cloud, kind = safety.is_cloud_or_placeholder(path)
    if cloud:
        return ("skipped", None, "list only (synced or placeholder): " + _clean(kind))
    gone = _keeper_problem(item)
    if gone:
        return ("deny", EXIT_STATE_CHANGED, gone)
    live = _live_reason(path, newest=newest, project=_project_of(item))
    if live:
        return ("deny", EXIT_LIVE_PROCESS, live)
    available, tool = platform_info.trash_available(path)
    if not available:
        return ("deny", EXIT_NO_TRASH, "no Trash for this volume: " + _clean(tool))
    if platform_info.os_kind() == "windows":
        risk = _windows_recycle_risk(path)
        if risk:
            return ("skipped", None, WINDOWS_BETA + risk)
    return None


def _archive_root() -> Path:
    return Path(os.path.expanduser("~")) / "corecleaner-archive"


def _prune_command(root: Path) -> Optional[str]:
    """A shell line that moves the archives `store_report` lists to the Trash, for the USER to run (never run here).

    One find over `<root>/<day>/<archive>` instead of a list of paths: it stays short (the agent view cuts
    strings at 300 characters) and `-mtime +89` is the same test as an age of 90 days or more. None where
    no Trash command is known.
    """
    kind = platform_info.os_kind()
    mover = {"macos": _MAC_TRASH + " -s -v", "linux": "gio trash --"}.get(kind)
    if mover is None:
        return None
    return "find -H %s -mindepth 2 -maxdepth 2 -type d -mtime +%d -exec %s {} +" % (
        shlex.quote(str(root)), archive.ARCHIVE_STALE_DAYS - 1, mover)


def _archive_store_note() -> Optional[dict]:
    """Size, cap and the archives older than 90 days of the archive store, plus a command for the user. Read-only.

    Archives are never deleted by this tool: each one can be the only copy of a repo's unsaved work.
    """
    root = _archive_root()
    try:
        if not root.is_dir():
            return None
        report = archive.store_report(root)
    except OSError:
        return None
    report["prune_command"] = _prune_command(root) if report["old_count"] else None
    report["note"] = (
        "corecleaner never deletes an archive; the ones in old are %d days or more untouched. "
        "The user may move them to the Trash with prune_command (the agent does not run it)." % archive.ARCHIVE_STALE_DAYS
    )
    return report


def _new_archive_dir(item_id: str) -> Path:
    day = _archive_root() / time.strftime("%Y%m%d", time.gmtime())
    day.mkdir(mode=0o700, parents=True, exist_ok=True)
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", str(item_id))[:60] or "item"
    for n in range(1, 100):
        candidate = day / (safe_id if n == 1 else "%s-%d" % (safe_id, n))
        try:
            candidate.mkdir(mode=0o700)
            return candidate
        except FileExistsError:
            continue
    raise CorecleanerError(EXIT_ERROR, "cannot allocate a fresh archive directory")


def _shown_name(item: dict) -> str:
    """What the agent sees as the item's name: derived from the path here, never copied from the plan."""
    path = item.get("path")
    if not isinstance(path, str):
        return "?"
    return safety.sanitize_name(os.path.basename(path.rstrip("/\\")) or path)


def _result(item: dict, status: str, reason: str, code: Optional[int] = None, dest: Optional[str] = None) -> dict:
    out = {
        "id": item.get("id"),
        "status": status,
        "reason": reason,
        "bytes": item.get("bytes") if isinstance(item.get("bytes"), int) else 0,
        "dest": dest,
        "display": _shown_name(item),
    }
    if code is not None:
        out["code"] = code
    return out


def _entry(item: dict, phase: str, dest: Optional[str] = None, error: Optional[str] = None, **extra: Any) -> dict:
    rec = {"id": item["id"], "phase": phase, "src": item["path"], "bytes": item.get("bytes"), "dest": dest, "error": error}
    rec.update(extra)
    return rec


def _repos_inside(item: dict) -> Tuple[List[str], Optional[str]]:
    """Repos whose work must be looked at before `item` goes to the Trash: (paths, problem).

    The item itself when it holds a .git; else, for the categories that can hold user work, every repo
    nested under it (a scratch folder is not a repo, but its sub-folders can be). A search that hit its
    limit is a problem, never "none found".
    """
    path = item["path"]
    if _looks_like_repo(path):
        return [path], None
    if os.path.isdir(path) and item.get("category") in plan_mod.CATEGORIES_SCANNED_INSIDE:
        found, truncated = inventory.find_repos(path, NESTED_REPO_DEPTH)
        if truncated:
            return [], "the search for repos inside it hit its limit: cannot prove it clean"
        return found, None
    return [], None


def _archive_needs(item: dict) -> Tuple[List[Tuple[str, str]], Optional[str]]:
    """([(repo, why)] to archive first, reason to refuse the whole item or None). Read-only."""
    repos, problem = _repos_inside(item)
    if problem:
        return [], problem
    if item.get("action") == "archive_then_trash" and not repos:
        # The plan promised an archive of unsaved work; no repo is here to archive. Never fall through to the Trash.
        return [], "the plan expected a repo with unsaved work here and none was found: not trashed"
    needs: List[Tuple[str, str]] = []
    for repo in repos:
        # Work that lives in a submodule or a linked worktree is lost with this folder even when the repo
        # itself is clean and published, and no archive of the repo covers it: refuse, do not archive.
        gaps = archive.incomplete(repo)
        if gaps:
            return [], "work outside what an archive covers (" + "; ".join(gaps) + "): not trashed"
        wants, why = archive.needs_archive(repo)
        if archive.PROTECTED_CUT_NOTE in why:
            # An ignored tree was too big to scan: a `.env` or a key in it would reach the Trash with no copy.
            # Clean or dirty, a repo whose scan did not finish is not trashed.
            return [], archive.PROTECTED_CUT_NOTE + ": cannot prove nothing unsaved is in it, not trashed"
        if wants:
            needs.append((repo, why))
    return needs, None


def _archive_reason(exc: CorecleanerError) -> Tuple[str, str]:
    """(status, fixed reason). Git and file-system text can carry words a repo author chose: it stays in the manifest."""
    if exc.code == EXIT_NO_SPACE_FOR_ARCHIVE:
        if exc.details.get("quota"):  # only sizes, no text from the repo: safe to show as it is
            return "skipped", _clean(exc.message) + " (not trashed)"
        return "skipped", "not enough free space for the archive, not trashed"
    if exc.details.get("unsafe_config"):
        return "skipped", "the repo's config can run programs, so it was not read or archived and is not trashed"
    return "failed", "archive failed, not trashed (details are in the run manifest)"


def _changed_while_archiving(item: dict, before: Tuple[float, int, bool]) -> Optional[str]:
    """Why the tree can no longer be trusted after a long archive, else None (SPEC trava 3, again)."""
    path = item["path"]
    why = _recheck(item)
    if why:
        return why
    try:
        after = plan_mod.tree_fingerprint(path)
    except OSError:
        return "no longer readable"
    if before[2] or after[2]:
        return "could not read the whole tree to prove it stayed idle"
    if after[:2] != before[:2]:
        return "files changed while it was being archived"
    return _live_reason(path, newest=after[0], project=_project_of(item))


def _identity(path: str) -> dict:
    st = os.lstat(path)
    return {
        "ino": st.st_ino,
        "dev": st.st_dev,
        "size": st.st_size if stat.S_ISREG(st.st_mode) else None,
        "mtime_ns": st.st_mtime_ns,  # undo falls back to it when the device number changed (disk replugged)
    }


def _apply_item(item: dict, run_id: str, trasher: Callable[[str], str]) -> Tuple[dict, Optional[Tuple[int, str]]]:
    """Archive if needed, then intent -> move -> done/fail. Returns (result, batch_stop or None)."""
    path = item["path"]
    needs, problem = _archive_needs(item)
    if problem:
        write_manifest(run_id, _entry(item, "fail", error="not trashed: " + problem))
        return _result(item, "skipped", problem), None
    extra: Dict[str, Any] = {}
    large_ignored = 0
    if needs:
        try:
            archive.check_quota(_archive_root(), [repo for repo, _why in needs])  # before anything is created
            before = plan_mod.tree_fingerprint(path)
            root_dir = _new_archive_dir(item["id"])
            for n, (repo, _why) in enumerate(needs, 1):
                slug = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(repo))[:40] or "repo"
                where = root_dir if (len(needs) == 1 and repo == path) else root_dir / ("%02d-%s" % (n, slug))
                info = archive.archive_repo(repo, str(where))
                large_ignored += len(info.get("ignored_large") or []) if isinstance(info, dict) else 0
                if isinstance(info, dict) and info.get("incomplete"):
                    raise CorecleanerError(EXIT_ERROR, "archive does not cover everything: " + "; ".join(info["incomplete"]), incomplete=True)
        except CorecleanerError as exc:
            extra_err = getattr(exc, "stderr", "")
            write_manifest(run_id, _entry(item, "fail", error=_clean("archive: %s %s" % (exc.message, extra_err), 600)))
            if exc.details.get("incomplete"):
                return _result(item, "skipped", "an archive would not cover everything: not trashed (the partial archive is kept)", exc.code), None
            status, reason = _archive_reason(exc)
            return _result(item, status, reason, exc.code), None
        except OSError as exc:
            write_manifest(run_id, _entry(item, "fail", error="archive: " + _clean(exc.strerror or exc, 200)))
            return _result(item, "failed", "archive failed, not trashed (details are in the run manifest)", EXIT_ERROR), None
        moved = _changed_while_archiving(item, before)
        if moved:
            write_manifest(run_id, _entry(item, "fail", error="changed while archiving: " + moved, archive=str(root_dir)))
            return _result(item, "deny", "changed while it was being archived: not trashed (archive kept)", EXIT_STATE_CHANGED), None
        extra["archive"] = str(root_dir)
    # The archive step above can take minutes: look once more right before the move, on every path
    late = _recheck(item) or _live_reason(path, newest=float(item.get("mtime") or 0.0), project=_project_of(item))
    if late:
        write_manifest(run_id, _entry(item, "fail", error="changed before the move: " + late))
        return _result(item, "deny", "changed before the move, not trashed: " + late, EXIT_STATE_CHANGED), None
    try:
        ident = _identity(path)
    except OSError:
        return _result(item, "deny", "no longer exists", EXIT_STATE_CHANGED), None
    extra.update(ident)
    write_manifest(run_id, _entry(item, "intent", **extra))
    try:
        dest = trasher(path)
    except DestinationUnknown as exc:
        write_manifest(run_id, _entry(item, "done", error="destination unknown: " + exc.message, **extra))
        res = _result(item, "ok", "moved to the Trash but destination unknown, undo not possible: " + _clean(exc.message))
        return res, (exc.code, exc.message)
    except CorecleanerError as exc:
        write_manifest(run_id, _entry(item, "fail", error=exc.message, **extra))
        return _result(item, "failed", _clean(exc.message), exc.code), (exc.code, exc.message)
    except Exception as exc:  # any surprise: record it and stop, never retry blindly
        msg = "%s: %s" % (type(exc).__name__, _clean(exc, 160))
        write_manifest(run_id, _entry(item, "fail", error=msg, **extra))
        return _result(item, "failed", msg, EXIT_ERROR), (EXIT_ERROR, msg)
    write_manifest(run_id, _entry(item, "done", dest=dest, **extra))
    reason = "moved to the Trash" + (" after archiving" if "archive" in extra else "")
    if large_ignored:
        reason += "; %d large ignored path(s) were NOT archived (listed in the archive MANIFEST.txt)" % large_ignored
    return _result(item, "ok", reason, dest=dest), None


def _dry_run_item(item: dict) -> dict:
    needs, problem = _archive_needs(item)
    if problem:
        return _result(item, "skipped", "would not be moved: " + problem)
    note = ""
    if needs:
        try:
            archive.check_quota(_archive_root(), [repo for repo, _why in needs])
        except CorecleanerError as exc:
            status, reason = _archive_reason(exc)
            return _result(item, status, "would not be moved: " + reason, exc.code)
        note = "; would archive %d repo(s) first (%s)" % (len(needs), _clean(needs[0][1], 160))
    return _result(item, "ok", "would move to the Trash" + note)


def _run_trash(args, trasher: Callable[[str], str]) -> dict:
    apply = bool(getattr(args, "apply", False))
    warnings = apply_guard(apply)
    plan = plan_mod.load_plan(args.plan)
    apply = bool(getattr(args, "apply", False))
    old = plan_mod.stale_reason("plan", plan.get("created"))
    if old and apply:
        raise CorecleanerError(EXIT_STATE_CHANGED, old, plan=_clean(args.plan, 200))
    by_id = {str(it.get("id")): it for it in plan.get("items", [])}
    wanted = list(dict.fromkeys(str(i) for i in (args.ids or [])))
    unknown = [i for i in wanted if i not in by_id]
    if not wanted:
        raise CorecleanerError(EXIT_USAGE, "no ids given")
    if unknown:
        raise CorecleanerError(EXIT_USAGE, "ids must come from the plan", unknown=[_clean(i, 40) for i in unknown[:20]])
    chosen = [it for it in plan["items"] if str(it.get("id")) in set(wanted)]
    run_id = "%s-%s" % (file_stamp(), os.urandom(2).hex()) if apply else None
    items: List[dict] = []
    stop: Optional[Tuple[int, str]] = None
    for item in chosen:
        if stop:
            items.append(_result(item, "skipped", "batch stopped after the first Trash failure"))
            continue
        try:
            verdict = _evaluate(item)
        except CorecleanerError as exc:
            verdict = ("deny", exc.code, exc.message)
        if verdict:
            status, code, reason = verdict
            items.append(_result(item, status, reason, code))
            if apply and code == EXIT_NO_TRASH:
                stop = (EXIT_NO_TRASH, reason)
            continue
        if not apply:
            items.append(_dry_run_item(item))
            continue
        res, stop = _apply_item(item, run_id, trasher)  # type: ignore[arg-type]
        items.append(res)
    trashed = sum(r["bytes"] for r in items if r["status"] == "ok") if apply else 0
    result: Dict[str, Any] = {
        "run_id": run_id,
        "apply": apply,
        "items": items,
        "apparent_bytes": trashed,  # a sum of per-path upper bounds, not the space the Trash will free
        "trashed_bytes": trashed,  # alias of apparent_bytes, kept for one release
        "not_ok": sum(1 for r in items if r["status"] != "ok"),  # corecleaner.main turns this into exit 46
        "note": NOTE_NOT_EMPTIED,
        "gain_note": plan_mod.GAIN_NOTE,
    }
    if not apply:
        result["would_trash_bytes"] = sum(r["bytes"] for r in items if r["status"] == "ok")
        if old:  # a dry run only warns: --apply would be refused
            warnings.append("--apply would be refused: " + old)
    if warnings:
        result["warnings"] = warnings
    store = _archive_store_note()
    if store:
        result["archive_store"] = store
    if stop:
        raise CorecleanerError(stop[0], "batch stopped: " + _clean(stop[1]), **result)
    return result


def run(args, trasher: Optional[Callable[[str], str]] = None) -> dict:
    cmd = getattr(args, "cmd", None)
    if cmd == "undo":
        return undo(args.run)
    if cmd == "trash":
        return _run_trash(args, trasher or send_to_trash)
    raise CorecleanerError(EXIT_USAGE, "trash module serves only 'trash' and 'undo'")
