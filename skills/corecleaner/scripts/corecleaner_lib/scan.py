"""Disk map: dua-cli when installed, basic scandir fallback otherwise. (T4; subcommand `scan`)

Read-only. Skips cloud folders and placeholders (safety.is_cloud_or_placeholder) and never
descends into them: reading a dataless file can download it.

run(args): args.roots (list[str] | None -> default_roots()), args.no_dua (bool), args.timeout
  (int seconds per dua call | None -> env CORECLEANER_SCAN_TIMEOUT -> DUA_TIMEOUT_S = 540), args.max_seconds
  (int wall-clock budget of the whole dua scan | None -> env CORECLEANER_SCAN_MAX_SECONDS -> none; what is
  left when it ends is "not measured"), args.ask_finder (bool, macOS: let Finder size an unreadable Trash).
  use_dua = dua found (platform_info.check()["dua"]) and not args.no_dua. A dua that cannot produce
  any size on its first call is dropped and the scan restarts in basic mode ("fallback" key); a
  timeout, a permission error or a spent budget is NOT a reason to drop dua.
  Returns {"tool": "dua"|"basic", "exact": bool, "complete": bool, "label": str, "tree": <node>,
  "read_bytes": int, "gap": {...}, "top": [<=20 entries by bytes], "snapshots": {...},
  "system_holds": [...], "skipped": {...}, "errors": [...], "warnings": [...], "unreadable_entries": int,
  "unmeasured_roots": [...], "roots": [...], "dropped_roots": [...], "dua": {...}|None, "seconds": float,
  "timing": [...], "ts": now_iso()}.
  complete is False when dua left unreadable entries (exit 1) or a root has no size (timeout, permission,
  budget); the label then starts with "partial scan (lower bound: ...)". exact keeps its own meaning
  (clones deduplicated or not). stderr gets a "still running" line every HEARTBEAT_S of a slow call.

scan(roots, use_dua, timeout=None) -> dict   (the "tree" value above, one synthetic root "(roots)")
  node = {"path": str, "bytes": int, "apparent": bool, "children": [node, ...]}  (+ "note", "pruned")
  bytes    = allocated bytes, hardlinks counted once.
  apparent = True when `bytes` is an upper bound (basic mode, or dua on macOS without clone dedup).
  dua mode: `dua aggregate -f bytes -x [--deduplicate-apfs-clones]`, flag only on macOS with dua
  >= 2.43.0. At most TWO passes over a root:
    pass 1  `dua aggregate ROOT`: one call. For a directory input dua prints its direct children
            plus a `total` line (no `total` when it has exactly one child), so this single call
            gives the exact root total (a clone-deduplicated total only exists as one invocation
            over the whole root) and every depth-1 size.
    pass 2  one batched call over the depth-2 folders of the depth-1 folders of at least
            DRILL_MIN_BYTES (split only when the argv would be too long; each path is still read once).
  The root total is exact; the per-folder split may vary (clone dedup is per invocation).
  A dua exit code 1 that still printed sizes (some entries unreadable: macOS privacy, EPERM) is
  accepted: the numbers are used and a warning "partial: N unreadable entries" is recorded. Any other
  non-zero exit (crash, SIGKILL, 101) may have cut the output short: its rows are dropped.
  A folder dua listed but whose name could not be matched (a newline, a name printed twice) is asked
  for alone (at most RETRY_MAX_PATHS per root), so one root may take a few more calls than two.
  Basic mode: os.scandir, symlinks not followed, same device only, st_blocks*512, each multiply
  linked inode once. Cannot see APFS clones: label "apparent (upper bound)", exact=False.
  Folders below PRUNE_BYTES are folded into the parent's "pruned" {count, bytes}; unreadable,
  cloud and other-filesystem folders stay as nodes with a "note" and bytes 0.
  bytes minus the sum of the children = files directly inside plus pruned folders.
  Nested roots are dropped (counted once, under the outer root).
  GAP = used bytes of each volume (shutil.disk_usage) minus the sum read on it, minus what
  system_holds measured outside the scanned roots ON THAT VOLUME (same device or same APFS container;
  gap.explained_by), never below zero because of a hold. A hold on another volume is listed in
  gap.held_elsewhere and not subtracted. gap.raw_unexplained_bytes is the figure before the subtraction.
  Label: "outside the scanned roots" when the roots do not cover the whole volume (no root is its mount
  point) or another volume of the same APFS container exists; "unexplained" only for a whole-volume scan.
  measure_outside(roots, ctx) lists what the roots miss (the shallowest folders below the mount point that
  no root contains: /private, other users, ...) and measures each with a same-device walk inside
  OUTSIDE_BUDGET_S (env CORECLEANER_SCAN_OUTSIDE_SECONDS, 0 = skip); gap.outside_roots is the biggest of
  them and gap.outside_roots_bytes is subtracted from gap.unexplained_bytes (after the holds, once).
  gap.other_volumes = volumes of the same container that no root reads (statvfs gives the container's
  figures on each of them, so they are listed and not sized).

system_holds(roots, snapshots, ask_finder=False) -> list of {"kind", "label", "bytes" (int|None),
  "measured" (bool), "in_gap" (bool: bytes known AND not read by the scan, so gap.explained_by subtracts
  it), "path" (where it lives, to pick the volume), "note", "action"}: swap (macOS sysctl vm.swapusage + files in /System/Volumes/VM,
  Linux /proc/swaps, Windows Get-CimInstance Win32_PageFileUsage), local snapshots (count only,
  sizes are not available) and the Trash when the scan cannot read it (macOS without Full Disk
  Access; the size is asked from Finder only with ask_finder, because that can raise a macOS permission
  prompt). Read-only; every action is for the human.

default_roots() -> list[str]
  macOS: HOME, /Applications, /Library, /opt, /usr/local. Linux: HOME, /var, /opt, /usr, /srv, /tmp.
  Windows: USERPROFILE, ProgramData, Program Files, TEMP and other fixed drives. Never "/". Roots
  that do not exist, are cloud folders or sit inside another root are dropped. Deny-listed roots
  are scanned read-only (listing is not deleting).

read_snapshots() -> dict
  What the OS holds as local snapshots: macOS `tmutil listlocalsnapshots /`, Linux btrfs
  `subvolume list -s` (when btrfs mounts exist), Windows `vssadmin list shadowstorage` (needs
  admin: the error is recorded, the scan goes on). Read-only; sizes are not available.
"""

from __future__ import annotations

import errno
import json
import os
import re
import shutil
import stat as statmod
import subprocess
import sys
import time
import unicodedata
from typing import Any, Dict, List, Optional, Set, Tuple

from . import platform_info, safety
from .common import EXIT_ERROR, CorecleanerError, log, now_iso

TOP_N = 20
MAX_DEPTH = 2
PRUNE_BYTES = 1 << 20
DRILL_MIN_BYTES = 128 << 20
REST_MIN_BYTES = 64 << 20
DUA_MIN_DEDUP = (2, 43, 0)
DUA_TIMEOUT_S = 540  # per dua call (a pass over a root, or one batch); under the 600 s cap of an agent's foreground shell
TIMEOUT_ENV = "CORECLEANER_SCAN_TIMEOUT"
MAX_SECONDS_ENV = "CORECLEANER_SCAN_MAX_SECONDS"  # wall-clock budget of the whole scan (dua mode); --max-seconds
HEARTBEAT_S = 30  # a command running longer than this prints a progress line on stderr every HEARTBEAT_S
CMD_TIMEOUT_S = 120  # tmutil, powershell: slow when the Mac is under memory pressure
FINDER_TIMEOUT_S = 30  # osascript to Finder: the first run can wait on a macOS permission prompt
QUICK_TIMEOUT_S = 15  # sysctl, dua --version
BATCH_MAX_PATHS = 1000
BATCH_MAX_CHARS = 120000  # argv budget per dua call (macOS ARG_MAX is 1 MiB)
RETRY_MAX_PATHS = 25
POOL_FREE_SLACK = 64 << 20  # paths of one APFS container report the same total and free, give or take this
MAX_ERRORS = 100
MAX_LISTED = 50
OUTSIDE_BUDGET_S = 20  # wall clock for measuring what the roots miss (the GAP); 0 measures nothing
OUTSIDE_ENV = "CORECLEANER_SCAN_OUTSIDE_SECONDS"
OUTSIDE_MAX_ENTRIES = 200  # missed top-level paths measured per volume
OUTSIDE_LISTED = 12  # of them kept in the result, biggest first
LABEL_UNEXPLAINED = "unexplained"
LABEL_OUTSIDE = "outside the scanned roots"

SF_DATALESS = 0x40000000
# OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS
WIN_PLACEHOLDER_ATTRS = 0x1000 | 0x40000 | 0x400000
WIN_REPARSE_POINT = 0x400
_DARWIN = sys.platform == "darwin"

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# "<bytes> b <name>" (dua 2.46.0 `-f bytes`); tolerant of padding, ANSI colour and human units. The name is
# everything after the ONE space that follows the unit: a leading or trailing space belongs to the name.
_DUA_LINE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(b|bytes?|[kmgtpe]i?b) (.+)$", re.IGNORECASE)
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
# dua appends two spaces and "<1 IO Error>" / "<2 IO Errors>" to a name (and to `total`) when entries were
# unreadable; a trailing space of the name itself stays in the name.
_IO_ERRORS_RE = re.compile(r"  <(\d+) IO Errors?>$", re.IGNORECASE)
_PERMISSION_RE = re.compile(r"operation not permitted|permission denied|os error (?:1|13)\b", re.IGNORECASE)


class _Unusable(Exception):
    """dua produced nothing on its very first call: scan again in basic mode."""


# --------------------------------------------------------------------------- parsing helpers


def _unit_factor(unit: str, binary: bool) -> int:
    u = unit.lower()
    if u in ("b", "byte", "bytes"):
        return 1
    power = "kmgtpe".index(u[0]) + 1
    return (1024 if binary or "i" in u else 1000) ** power


def _to_bytes(number: str, unit: str, binary: bool = False) -> int:
    factor = _unit_factor(unit, binary)
    if "." not in number:
        return int(number) * factor
    return int(round(float(number) * factor))


def parse_dua_rows(text: str) -> List[Tuple[int, str, int]]:
    """[(bytes, name, io_errors), ...] in output order; the "<N IO Error>" suffix is cut off the name."""
    rows = []  # type: List[Tuple[int, str, int]]
    for raw in _ANSI_RE.sub("", text).splitlines():
        match = _DUA_LINE_RE.match(raw)
        if not match:
            continue
        name = match.group(3)
        flagged = _IO_ERRORS_RE.search(name)
        if flagged:
            name = name[: flagged.start()]
        rows.append((_to_bytes(match.group(1), match.group(2)), name, int(flagged.group(1)) if flagged else 0))
    return rows


def parse_dua_output(text: str) -> List[Tuple[int, str]]:
    """[(bytes, name), ...] in output order from `dua aggregate -f bytes`; unknown lines are ignored."""
    return [(nbytes, name) for nbytes, name, _ in parse_dua_rows(text)]


def _by_name(rows: List[Tuple[int, str]], key: Any = os.path.basename) -> Dict[str, Optional[int]]:
    """{key(name): bytes}; a key that shows up twice maps to None because nobody can tell whose row is whose."""
    kids = {}  # type: Dict[str, Optional[int]]
    for nbytes, name in rows:
        k = key(name)
        kids[k] = None if k in kids else nbytes
    return kids


def split_listing(rows: List[Tuple[int, str]]) -> Tuple[int, Dict[str, Optional[int]]]:
    """(total, {child name: bytes | None}) from the rows of ONE directory input.

    dua lists the children of a single directory and ends with `total`; with exactly one child it
    prints that child and no `total`, with no child it prints nothing. A name that appears twice
    (a name with a newline is printed as two lines, or two names collapse to one key) maps to None
    and the caller asks dua again for that folder alone.
    """
    if not rows:
        return 0, {}
    if len(rows) >= 2 and rows[-1][1].lower() == "total":
        return rows[-1][0], _by_name(rows[:-1])
    return sum(nbytes for nbytes, _ in rows), _by_name(rows)


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def parse_version(text: Optional[str]) -> Optional[Tuple[int, int, int]]:
    match = _VERSION_RE.search(text or "")
    return tuple(int(g) for g in match.groups()) if match else None  # type: ignore[return-value]


def dedup_supported(version: Optional[str]) -> bool:
    parsed = parse_version(version)
    return parsed is not None and parsed >= DUA_MIN_DEDUP


def _parse_number(text: str) -> float:
    t = text.strip()
    if "," in t and "." in t:
        if t.rfind(",") > t.rfind("."):
            t = t.replace(".", "").replace(",", ".")
        else:
            t = t.replace(",", "")
    elif "," in t:
        head, _, tail = t.rpartition(",")
        t = t.replace(",", "") if len(tail) == 3 else head.replace(",", "") + "." + tail
    return float(t)


def _run_cmd(argv: List[str], timeout: float = CMD_TIMEOUT_S) -> Tuple[Optional[int], str, str]:
    """(returncode | None, stdout, stderr); None means it could not run (missing, timeout).

    Past HEARTBEAT_S the command is still waited for, and a line "<name> still running (Ns of Ms)" goes
    to stderr every HEARTBEAT_S so a long call never looks hung. Only argv[0]'s base name is printed.
    """
    started = time.monotonic()
    try:
        with subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as proc:  # the with block closes the pipes and reaps the child, also after a kill
            while True:
                left = timeout - (time.monotonic() - started)
                try:
                    out, err = proc.communicate(timeout=max(0.01, min(HEARTBEAT_S, left)))
                    break
                except subprocess.TimeoutExpired:
                    elapsed = time.monotonic() - started
                    if elapsed >= timeout:
                        proc.kill()
                        return None, "", "timed out after %ds" % timeout
                    log("  %s still running (%ds of %ds)" % (os.path.basename(argv[0]), elapsed, timeout))
    except FileNotFoundError:
        return None, "", "not found: " + argv[0]
    except OSError as exc:
        return None, "", exc.strerror or type(exc).__name__
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


# --------------------------------------------------------------------------- paths and roots


def _home() -> str:
    if os.name == "nt":
        return os.environ.get("USERPROFILE") or os.path.expanduser("~")
    return os.path.expanduser("~")


def _real(path: str) -> str:
    return os.path.realpath(os.path.expanduser(path))


def _within(child: str, parent: str) -> bool:
    c, p = os.path.normcase(child), os.path.normcase(parent)
    return c == p or c.startswith(p.rstrip(os.sep) + os.sep)


def _windows_fixed_drives() -> List[str]:
    try:
        import ctypes

        kernel = ctypes.windll.kernel32  # type: ignore[attr-defined]
        mask = kernel.GetLogicalDrives()
        drives = []
        for i in range(26):
            root = chr(65 + i) + ":\\"
            if mask & (1 << i) and kernel.GetDriveTypeW(root) == 3:  # DRIVE_FIXED
                drives.append(root)
        return drives
    except Exception:
        return []


def _prepare_roots(roots: List[str]) -> Tuple[List[str], List[Dict[str, str]]]:
    """(kept, dropped): realpaths of existing, non-cloud roots; a root inside another is dropped."""
    kept = []  # type: List[str]
    dropped = []  # type: List[Dict[str, str]]
    for raw in roots:
        path = _real(raw)
        if not os.path.isdir(path):
            dropped.append({"path": path, "reason": "not a directory"})
            continue
        cloud, why = safety.is_cloud_or_placeholder(path)
        if cloud:
            dropped.append({"path": path, "reason": "cloud or placeholder: " + why})
            continue
        outer = next((k for k in kept if _within(path, k)), None)
        if outer is not None:
            dropped.append({"path": path, "reason": "inside root " + outer})
            continue
        for inner in [k for k in kept if _within(k, path)]:
            kept.remove(inner)
            dropped.append({"path": inner, "reason": "inside root " + path})
        kept.append(path)
    return kept, dropped


def default_roots() -> List[str]:
    kind = platform_info.os_kind()
    home = _home()
    if kind == "macos":
        candidates = [home, "/Applications", "/Library", "/opt", "/usr/local"]
    elif kind == "linux":
        candidates = [home, "/var", "/opt", "/usr", "/srv", "/tmp"]
    else:
        env = os.environ
        candidates = [home]
        for name in ("ProgramData", "ProgramFiles", "ProgramFiles(x86)", "TEMP"):
            if env.get(name):
                candidates.append(env[name])
        system_drive = env.get("SystemDrive", "C:").rstrip("\\/").upper()
        candidates += [d for d in _windows_fixed_drives() if d.rstrip("\\/").upper() != system_drive]
    return _prepare_roots(candidates)[0]


# --------------------------------------------------------------------------- scan state and nodes


def _node(path: str, nbytes: int, apparent: bool, note: Optional[str] = None) -> Dict[str, Any]:
    node = {"path": path, "bytes": nbytes, "apparent": apparent, "children": []}  # type: Dict[str, Any]
    if note:
        node["note"] = note
    return node


class _Dua:
    def __init__(
        self, path: str, version: Optional[str], dedup: bool, exact: bool, timeout: int = DUA_TIMEOUT_S
    ) -> None:
        self.path = path
        self.version = version
        self.dedup = dedup
        self.exact = exact
        self.timeout = timeout
        self.good_calls = 0

    def _argv(self, paths: List[str], ignore: List[str]) -> List[str]:
        argv = [self.path, "aggregate", "-f", "bytes", "-x"]
        if self.dedup:
            argv.append("--deduplicate-apfs-clones")
        # Attached value (-iPATH): a detached one could swallow the positional paths.
        argv += ["-i" + p for p in ignore]
        return argv + ["--"] + paths

    def _call(self, paths: List[str], ignore: List[str], ctx: "_Ctx") -> Optional[List[Tuple[int, str]]]:
        """Rows of one dua call, or None when it gave nothing usable (the failure is already recorded).

        Exit 0 is a complete answer. Exit 1 with parseable rows means "some entries unreadable": the
        rows are kept and a warning is recorded. Any other exit (a crash, SIGKILL, 101) or a timeout
        gives rows that may be cut short, so they are dropped. A timeout, a permission error or a
        spent time budget never drops dua for the whole scan; only a first call that yields nothing does.
        """
        relevant = [i for i in ignore if any(_within(i, p) for p in paths)]
        limit = ctx.time_left(self.timeout)
        if limit <= 0:
            ctx.budget_spent = True
            ctx.error(paths[0], "time budget used up (--max-seconds): not measured")
            return None
        rc, out, err = _run_cmd(self._argv(paths, relevant), limit)
        parsed = parse_dua_rows(out) if rc is not None else []
        rows = [(nbytes, name) for nbytes, name, _ in parsed]
        detail = safety.sanitize_name(_first_line(err), 160)
        if rc is None:
            if err.startswith("timed out"):
                if limit < self.timeout:
                    ctx.budget_spent = True
                    ctx.error(paths[0], "time budget used up (--max-seconds) while dua was running: not measured")
                else:
                    ctx.error(
                        paths[0], "dua timed out after %ds (raise it with --timeout or %s)" % (self.timeout, TIMEOUT_ENV)
                    )
                return None
            if self.good_calls == 0:
                raise _Unusable("dua gave no size on its first call: " + detail)
            ctx.error(paths[0], "dua failed: " + detail)
            return None
        if rc not in (0, 1) or (rc == 1 and not rows):
            if rc == 1 and _PERMISSION_RE.search(err):
                ctx.error(paths[0], "unreadable: " + detail)
                return None
            why = "dua exited %d" % rc + (" (its %d rows were cut short and dropped)" % len(rows) if rows else "")
            if self.good_calls == 0:
                raise _Unusable("%s on its first call%s" % (why, ": " + detail if detail else ""))
            ctx.error(paths[0], "%s%s" % (why, ": " + detail if detail else ""))
            return None
        if rc == 1:
            total_row = next((p for p in reversed(parsed) if p[1].lower() == "total"), None)
            unreadable = total_row[2] if total_row else sum(p[2] for p in parsed)
            ctx.partial(paths[0], unreadable)
        self.good_calls += 1
        return rows

    def listing(self, root: str, ignore: List[str], ctx: "_Ctx") -> Optional[Tuple[int, Dict[str, Optional[int]]]]:
        """Pass 1: (exact total of `root`, {direct child name (NFC): bytes | None}) from ONE call."""
        rows = self._call([root], ignore, ctx)
        if rows is None:
            return None
        total, children = split_listing(rows)
        by_nfc = {}  # type: Dict[str, Optional[int]]
        for name, nbytes in children.items():
            key = _nfc(name)
            by_nfc[key] = None if key in by_nfc or nbytes is None else nbytes
        return total, by_nfc

    @staticmethod
    def _assign(result: Dict[str, Optional[int]], paths: List[str], rows: List[Tuple[int, str]]) -> bool:
        """Fill `result` from a call over `paths`; True when every path got a size."""
        if len(paths) == 1:  # one directory is listed by its children: the size is the `total`
            result[paths[0]] = split_listing(rows)[0]
            return True
        by_key = {_nfc(os.path.normcase(os.path.normpath(p))): p for p in paths}
        sized = _by_name(
            [(nbytes, name) for nbytes, name in rows if name.lower() != "total"],
            key=lambda name: _nfc(os.path.normcase(os.path.normpath(name))),
        )
        for key, nbytes in sized.items():  # a name printed twice (a newline in a path) stays unknown
            orig = by_key.get(key)
            if orig is not None and result[orig] is None:
                result[orig] = nbytes
        return all(result[p] is not None for p in paths)

    @staticmethod
    def _chunks(paths: List[str]) -> List[List[str]]:
        chunks = []  # type: List[List[str]]
        current = []  # type: List[str]
        chars = 0
        for path in paths:
            if current and (len(current) >= BATCH_MAX_PATHS or chars + len(path) > BATCH_MAX_CHARS):
                chunks.append(current)
                current, chars = [], 0
            current.append(path)
            chars += len(path) + 1
        if current:
            chunks.append(current)
        return chunks

    def sizes(self, paths: List[str], ignore: List[str], ctx: "_Ctx") -> Dict[str, Optional[int]]:
        """Pass 2: sizes of folders, one batched call (chunked only when the argv would be too long).

        A path whose row did not come back by name is asked again on its own, but only when its
        batch answered (a timed out batch is not repeated path by path) and for a few paths.
        """
        result = {p: None for p in paths}  # type: Dict[str, Optional[int]]
        answered = []  # type: List[str]
        for chunk in self._chunks(paths):
            rows = self._call(chunk, ignore, ctx)
            if rows is not None:
                answered.extend(chunk)
                self._assign(result, chunk, rows)
        if len(paths) > 1:
            missing = [p for p in answered if result[p] is None]
            if len(missing) <= RETRY_MAX_PATHS:
                for path in missing:
                    rows = self._call([path], ignore, ctx)
                    if rows is not None:
                        self._assign(result, [path], rows)
        return result


class _Ctx:
    def __init__(self, dua: Optional[_Dua]) -> None:
        self.dua = dua
        self.apparent = dua is None or not dua.exact
        self.errors = []  # type: List[Dict[str, str]]
        self.errors_total = 0
        self.warnings = []  # type: List[Dict[str, Any]]
        self.warnings_total = 0
        self.unreadable_total = 0
        self.timings = []  # type: List[Dict[str, Any]]
        self.cloud = []  # type: List[str]
        self.other_fs = []  # type: List[str]
        self.placeholder_files = 0
        self.ignore = []  # type: List[str]
        self.seen = set()  # type: Set[Tuple[int, int]]
        self.unmeasured = []  # type: List[str]  # roots whose total could not be read: not zero, unknown
        self.budget_spent = False
        self.deadline = None  # type: Optional[float]  # clock() value at which the --max-seconds budget ends
        self.clock = time.monotonic

    def time_left(self, cap: float) -> float:
        """Seconds one more call may take: `cap`, or what is left of the budget when that is smaller."""
        if self.deadline is None:
            return cap
        return min(cap, self.deadline - self.clock())

    def error(self, path: str, message: str) -> None:
        self.errors_total += 1
        if len(self.errors) < MAX_ERRORS:
            self.errors.append({"path": path, "error": message})

    def partial(self, path: str, unreadable: int) -> None:
        """dua exited 1 but printed sizes: keep them, say how many entries it could not read."""
        self.warnings_total += 1
        self.unreadable_total += unreadable
        message = "partial: %d unreadable entries" % unreadable if unreadable else "partial: dua exit 1, some entries unreadable"
        if len(self.warnings) < MAX_ERRORS:
            self.warnings.append({"path": path, "warning": message, "unreadable_entries": unreadable})


def _make_dua(info: Optional[Dict[str, Any]], timeout: int = DUA_TIMEOUT_S) -> Optional[_Dua]:
    if not info or not info.get("found") or not info.get("path"):
        return None
    path = str(info["path"])
    version = info.get("version")
    if not version:
        rc, out, _ = _run_cmd([path, "--version"], QUICK_TIMEOUT_S)
        version = out.strip() if rc == 0 else None
    mac = platform_info.os_kind() == "macos"
    dedup = mac and dedup_supported(version)
    return _Dua(path, version, dedup, exact=(not mac) or dedup, timeout=timeout)


# --------------------------------------------------------------------------- directory handling


def _is_placeholder_stat(st: Any, darwin: bool) -> bool:
    if darwin and getattr(st, "st_flags", 0) & SF_DATALESS:
        return True
    return bool(getattr(st, "st_file_attributes", 0) & WIN_PLACEHOLDER_ATTRS)


def _allocated(st: Any) -> int:
    blocks = getattr(st, "st_blocks", None)
    if blocks is not None:
        return int(blocks) * 512
    return (st.st_size + 4095) // 4096 * 4096  # Windows: no st_blocks, assume 4 KiB clusters


def _dir_skip_reason(path: str, st: Any, dev: int, ctx: _Ctx) -> Optional[str]:
    """Why a directory must not be entered (None = enter). Uses the lstat already taken."""
    if getattr(st, "st_file_attributes", 0) & WIN_REPARSE_POINT:
        ctx.other_fs.append(path)
        return "reparse point (junction or mount), not followed"
    if st.st_dev and dev and st.st_dev != dev:
        ctx.other_fs.append(path)
        return "other filesystem, not entered"
    if _is_placeholder_stat(st, _DARWIN):
        reason = "dataless placeholder, list only"
    else:
        cloud, why = safety.is_cloud_or_placeholder(path)
        if not cloud:
            return None
        reason = "cloud or placeholder, list only: " + why
    ctx.cloud.append(path)
    if path not in ctx.ignore:
        ctx.ignore.append(path)
    return reason


def _list_dirs(path: str, dev: int, ctx: _Ctx) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Sub-directories of `path` to enter, plus nodes for those listed but never entered."""
    dirs = []  # type: List[str]
    skipped = []  # type: List[Dict[str, Any]]
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    st = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    ctx.error(entry.path, exc.strerror or "error")
                    continue
                reason = _dir_skip_reason(entry.path, st, dev, ctx)
                if reason:
                    skipped.append(_node(entry.path, 0, ctx.apparent, reason))
                else:
                    dirs.append(entry.path)
    except OSError as exc:
        ctx.error(path, exc.strerror or "error")
    return sorted(dirs), skipped


def _unreadable_root(root: str, exc: OSError, ctx: _Ctx) -> Dict[str, Any]:
    message = exc.strerror or "error"
    ctx.error(root, message)
    ctx.unmeasured.append(root)
    return _node(root, 0, ctx.apparent, "unreadable: " + message)


# --------------------------------------------------------------------------- dua mode


def _scan_root_dua(root: str, ctx: _Ctx) -> Dict[str, Any]:
    dua = ctx.dua
    assert dua is not None
    try:
        dev = os.lstat(root).st_dev
    except OSError as exc:
        return _unreadable_root(root, exc, ctx)
    subs1, skipped1 = _list_dirs(root, dev, ctx)
    # Listing depth 2 up front lets every cloud folder reach `-i` before the first dua call.
    listing2 = {d: _list_dirs(d, dev, ctx) for d in subs1}
    log("  %s: pass 1/2, total and top level (timeout %ds per call)" % (root, dua.timeout))
    listing = dua.listing(root, ctx.ignore, ctx)
    if listing is None:
        ctx.unmeasured.append(root)
        node = _node(root, 0, ctx.apparent, "no size from dua")
        node["children"].extend(skipped1)
        return node
    total, by_name = listing
    node = _node(root, total, ctx.apparent)
    sizes1 = {p: by_name.get(_nfc(os.path.basename(p))) for p in subs1}
    # A folder with no size (a name dua printed twice, cut in two lines or with a suffix that looks like its
    # own) is asked for alone, a few at most: its row exists, only the match by name failed.
    lost = [p for p in subs1 if sizes1[p] is None]
    if lost and len(lost) <= RETRY_MAX_PATHS:
        sizes1.update(dua.sizes(lost, ctx.ignore, ctx))
    big = [p for p in subs1 if sizes1[p] is not None and sizes1[p] >= DRILL_MIN_BYTES]  # type: ignore[operator]
    batch = [sub for p in big for sub in listing2[p][0]]
    log("  %s: pass 2/2, %d folders under %d big ones" % (root, len(batch), len(big)))
    sizes2 = dua.sizes(batch, ctx.ignore, ctx)
    for path in subs1:
        size = sizes1[path]
        child = _node(path, size or 0, ctx.apparent, None if size is not None else "no size from dua")
        if path in big:
            subs2, skipped2 = listing2[path]
            for sub in subs2:
                sub_size = sizes2[sub]
                note = None if sub_size is not None else "no size from dua"
                child["children"].append(_node(sub, sub_size or 0, ctx.apparent, note))
            child["children"].extend(skipped2)
        node["children"].append(child)
    node["children"].extend(skipped1)
    return node


# --------------------------------------------------------------------------- basic mode


def _visit(entry: Any, owner: Dict[str, Any], depth: int, dev: int, ctx: _Ctx, stack: list) -> None:
    try:
        st = entry.stat(follow_symlinks=False)
    except OSError as exc:
        ctx.error(entry.path, exc.strerror or "error")
        return
    if statmod.S_ISDIR(st.st_mode):
        child_depth = depth + 1
        reason = _dir_skip_reason(entry.path, st, dev, ctx)
        if reason:
            if child_depth <= MAX_DEPTH:
                owner["children"].append(_node(entry.path, 0, True, reason))
            return
        if child_depth <= MAX_DEPTH:
            child = _node(entry.path, 0, True)
            child["_own"] = _allocated(st)
            owner["children"].append(child)
            stack.append((entry.path, child, child_depth))
        else:
            owner["_own"] += _allocated(st)
            stack.append((entry.path, owner, child_depth))
        return
    if _is_placeholder_stat(st, _DARWIN):
        ctx.placeholder_files += 1
        return
    if st.st_nlink > 1 and st.st_ino:
        key = (st.st_dev, st.st_ino)
        if key in ctx.seen:
            return
        ctx.seen.add(key)
    owner["_own"] += _allocated(st)


def _finalize(node: Dict[str, Any]) -> int:
    total = node.pop("_own", 0)
    for child in node["children"]:
        total += _finalize(child)
    node["bytes"] = total
    return total


def _scan_root_basic(root: str, ctx: _Ctx) -> Dict[str, Any]:
    try:
        st = os.lstat(root)
    except OSError as exc:
        return _unreadable_root(root, exc, ctx)
    top = _node(root, 0, True)
    top["_own"] = _allocated(st)
    stack = [(root, top, 0)]  # type: list
    while stack:
        path, owner, depth = stack.pop()
        try:
            with os.scandir(path) as it:
                for entry in it:
                    _visit(entry, owner, depth, st.st_dev, ctx, stack)
        except OSError as exc:
            message = exc.strerror or "error"
            ctx.error(path, message)
            if owner["path"] == path:
                owner.setdefault("note", "unreadable: " + message)
    _finalize(top)
    return top


# --------------------------------------------------------------------------- tree, gap, top


def _prune(node: Dict[str, Any]) -> None:
    kept = []
    count, folded = 0, 0
    for child in node["children"]:
        _prune(child)
        if child["bytes"] < PRUNE_BYTES and "note" not in child:
            count += 1
            folded += child["bytes"]
        else:
            kept.append(child)
    kept.sort(key=lambda c: c["bytes"], reverse=True)
    node["children"] = kept
    if count:
        node["pruned"] = {"count": count, "bytes": folded}


def _scan_all(roots: List[str], ctx: _Ctx) -> Dict[str, Any]:
    nodes = []
    for root in roots:
        log("scanning %s (%s)" % (root, "dua" if ctx.dua else "basic"))
        started = time.monotonic()
        node = _scan_root_dua(root, ctx) if ctx.dua else _scan_root_basic(root, ctx)
        _prune(node)
        nodes.append(node)
        ctx.timings.append({"root": root, "seconds": round(time.monotonic() - started, 1)})
    return {"path": "(roots)", "bytes": sum(n["bytes"] for n in nodes), "apparent": ctx.apparent, "children": nodes}


def _same_pool(a: str, b: str) -> bool:
    """True when `a` and `b` draw on the same free space: one device, or volumes of one APFS container
    (different st_dev, same total and same free). A swap file on another disk is not part of this disk's GAP."""
    try:
        dev_a, dev_b = os.stat(a).st_dev, os.stat(b).st_dev
        if dev_a and dev_a == dev_b:
            return True
        use_a, use_b = shutil.disk_usage(a), shutil.disk_usage(b)
    except OSError:
        return False
    return use_a.total == use_b.total and abs(use_a.free - use_b.free) <= POOL_FREE_SLACK


def _outside_budget() -> float:
    """Seconds to spend measuring what the roots miss: env CORECLEANER_SCAN_OUTSIDE_SECONDS (0 = measure nothing), else OUTSIDE_BUDGET_S."""
    raw = os.environ.get(OUTSIDE_ENV)
    if raw not in (None, ""):
        try:
            value = float(raw)
        except ValueError:
            value = -1.0
        if value >= 0:
            return value
        log("ignoring invalid outside-roots budget %r" % (raw,))
    return float(OUTSIDE_BUDGET_S)


def _mount_rows() -> List[Dict[str, Any]]:
    return platform_info._mounts()


def _mount_of(path: str) -> Optional[str]:
    vol = platform_info._volume(path)
    return vol["mount"] if vol else None


def _seen_from(mount: str, root: str) -> Optional[str]:
    """`root` as it appears below `mount`. APFS firmlinks show /Users/me again as /System/Volumes/Data/Users/me;
    the same device and inode prove it is the same folder, anything else is not this volume's."""
    if _within(root, mount):
        return root
    candidate = os.path.normpath(mount + root)
    try:
        a, b = os.stat(root), os.stat(candidate)
    except OSError:
        return None
    return candidate if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) else None


def _missed_entries(mount: str, covered: List[str], mount_points: Set[str]) -> Tuple[List[str], int]:
    """Shallowest paths below `mount` that no scanned root contains (a folder holding a root is opened, not counted).
    Other mounted volumes are not part of this one. Second value: folders that could not be listed."""
    missed = []  # type: List[str]
    unreadable = 0
    stack = [mount]
    while stack:
        folder = stack.pop()
        try:
            with os.scandir(folder) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            unreadable += 1
            continue
        for entry in entries:
            path = entry.path
            if path in covered or (path in mount_points and path != mount):
                continue
            if any(_within(c, path) for c in covered):
                try:
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(path)
                except OSError:
                    unreadable += 1
                continue
            missed.append(path)
    return missed, unreadable


def _measure_missed(
    path: str, dev: int, deadline: float, seen: Set[Tuple[int, int]], mount_points: Set[str], clock: Any
) -> Tuple[int, bool, int]:
    """(allocated bytes, finished, unreadable) of one missed path. Same device only, links and mounts not followed,
    placeholders and cloud folders not entered, each hard-linked inode once. Stops at `deadline` (finished False)."""
    try:
        st = os.lstat(path)
    except OSError:
        return 0, True, 1
    if not statmod.S_ISDIR(st.st_mode):
        if statmod.S_ISLNK(st.st_mode) or _is_placeholder_stat(st, _DARWIN):
            return 0, True, 0
        if st.st_nlink > 1 and st.st_ino:
            key = (st.st_dev, st.st_ino)
            if key in seen:
                return 0, True, 0
            seen.add(key)
        return _allocated(st), True, 0
    scratch = _Ctx(None)  # _dir_skip_reason records what it skips; this walk keeps none of it
    if _dir_skip_reason(path, st, dev, scratch):
        return 0, True, 0
    total, unreadable, ticks = _allocated(st), 0, 0
    stack = [path]
    while stack:
        folder = stack.pop()
        try:
            with os.scandir(folder) as it:
                for entry in it:
                    ticks += 1
                    if ticks % 256 == 0 and clock() > deadline:
                        return total, False, unreadable
                    try:
                        est = entry.stat(follow_symlinks=False)
                    except OSError:
                        unreadable += 1
                        continue
                    if statmod.S_ISDIR(est.st_mode):
                        if entry.path in mount_points or _dir_skip_reason(entry.path, est, dev, scratch):
                            continue
                        total += _allocated(est)
                        stack.append(entry.path)
                        continue
                    if _is_placeholder_stat(est, _DARWIN):
                        continue
                    if est.st_nlink > 1 and est.st_ino:
                        key = (est.st_dev, est.st_ino)
                        if key in seen:
                            continue
                        seen.add(key)
                    total += _allocated(est)
        except OSError:
            unreadable += 1
    return total, True, unreadable


def _other_volumes(mount: str, rows: List[Dict[str, Any]], skip: Set[str]) -> List[Dict[str, Any]]:
    """Volumes of the same APFS container that no root reads. statvfs reports the whole container on each of them
    (measured on macOS 26: System, Data, VM, Preboot and Update all return one total and one used), so none can
    be sized from here."""
    mine = next((r for r in reversed(rows) if r.get("mount") == mount), None)
    if mine is None or not str(mine.get("device", "")).startswith("/dev/"):
        return []
    found = []  # type: List[Dict[str, Any]]
    for row in rows:
        other = row.get("mount")
        if (
            not other or other == mount or other in skip
            or row.get("device") == mine.get("device")
            or not str(row.get("device", "")).startswith("/dev/")  # a snapshot mounted for Time Machine has no device node
            or row.get("fs") != mine.get("fs")
            or not _same_pool(other, mount)
        ):
            continue
        found.append({"mount": other, "fs": row.get("fs"), "bytes": None})
    return found


def measure_outside(roots: List[str], ctx: Optional[_Ctx] = None, clock: Any = time.monotonic) -> Dict[str, Any]:
    """What the roots do not cover, on the volume of each root group (read-only, never above the budget).

    Per volume: the shallowest folders below its mount point that no root contains (/private, other users, ...),
    each measured by a same-device walk that gets an equal share of the time left (entries: every one measured,
    biggest first, with its real path under "abs"). A volume counts as covered
    only when a root is its mount point. Besides: other volumes of the same APFS container, listed and not sized.
    Windows measures nothing (a drive root is the only full cover)."""
    started = clock()
    configured = _outside_budget()
    budget = configured if ctx is None else min(configured, max(ctx.time_left(configured), 0.0))
    groups = {}  # type: Dict[Any, Dict[str, Any]]
    for root in roots:
        try:
            key = os.stat(root).st_dev  # type: Any
        except OSError:
            key = ("path", root)
        groups.setdefault(key, {"path": root, "roots": [], "dev": key if isinstance(key, int) else 0})["roots"].append(root)
    rows = []  # type: List[Dict[str, Any]]
    if os.name != "nt":
        try:
            rows = _mount_rows()
        except (OSError, ValueError):
            rows = []
    mount_points = {r["mount"] for r in rows if r.get("mount")}
    volumes = []  # type: List[Dict[str, Any]]
    scanned_mounts = set()  # type: Set[str]
    others = []  # type: List[Dict[str, Any]]
    for group in groups.values():
        vol = {
            "path": group["path"], "mount": None, "partial": True, "entries": [], "entries_total": 0,
            "bytes": 0, "complete": True, "unmeasured": 0, "unreadable": 0, "note": None,
        }  # type: Dict[str, Any]
        volumes.append(vol)
        if os.name == "nt":
            vol["partial"] = not any(os.path.splitdrive(r)[1] in ("", "\\", "/") for r in group["roots"])
            vol["complete"] = False
            vol["note"] = "not measured on Windows"
            continue
        try:
            mount = _mount_of(group["path"])
        except OSError:
            mount = None
        if mount is None:
            vol["complete"] = False
            vol["note"] = "volume not identified: what the roots miss was not measured"
            continue
        vol["mount"] = mount
        scanned_mounts.add(mount)
        seen_from = [_seen_from(mount, r) for r in group["roots"]]
        covered = [c for c in seen_from if c]
        vol["partial"] = mount not in covered or any(c is None for c in seen_from)
        if any(c is None for c in seen_from):
            vol["note"] = "a root is on another volume of the same device: not measured"
        if not vol["partial"]:
            continue
        if budget <= 0:
            vol["complete"] = False
            vol["note"] = "not measured (%s)" % (
                "%s=0" % OUTSIDE_ENV if configured <= 0 else "the --max-seconds budget of the scan is spent"
            )
            continue
        log("  measuring what the roots do not cover on %s (up to %d s)" % (mount, budget))
        missed, unlistable = _missed_entries(mount, covered, mount_points)
        vol["unreadable"] += unlistable
        vol["entries_total"] = len(missed)
        todo = missed[:OUTSIDE_MAX_ENTRIES]
        vol["unmeasured"] += len(missed) - len(todo)
        seen = set()  # type: Set[Tuple[int, int]]
        dev = group["dev"]
        end = started + budget
        measured = []  # type: List[Dict[str, Any]]
        for index, path in enumerate(todo):
            left = end - clock()
            if left <= 0:
                vol["unmeasured"] += len(todo) - index
                break
            nbytes, done, bad = _measure_missed(path, dev, clock() + left / (len(todo) - index), seen, mount_points, clock)
            vol["unreadable"] += bad
            measured.append(
                {
                    "path": "/" + os.path.relpath(path, mount) if mount != "/" else path,
                    "abs": path, "bytes": nbytes, "complete": done and not bad,
                }
            )
        measured.sort(key=lambda e: e["bytes"], reverse=True)
        vol["bytes"] = sum(e["bytes"] for e in measured)
        vol["entries"] = measured
        vol["complete"] = vol["unmeasured"] == 0 and vol["unreadable"] == 0 and all(e["complete"] for e in measured)
    for mount in sorted(scanned_mounts):
        for other in _other_volumes(mount, rows, scanned_mounts):
            if not any(o["mount"] == other["mount"] for o in others):
                others.append(other)
    return {
        "partial": any(v["partial"] for v in volumes),
        "volumes": volumes,
        "other_volumes": others,
        "bytes": sum(v["bytes"] for v in volumes),
        "complete": all(v["complete"] for v in volumes),
        "seconds": round(clock() - started, 1),
        "budget_s": round(budget, 1),
    }


def _gap(
    root_nodes: List[Dict[str, Any]],
    ctx: _Ctx,
    holds: Optional[List[Dict[str, Any]]] = None,
    outside: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    groups = {}  # type: Dict[Any, Dict[str, Any]]
    for node in root_nodes:
        try:
            key = os.stat(node["path"]).st_dev  # type: Any
        except OSError:
            key = ("path", node["path"])
        group = groups.setdefault(key, {"path": node["path"], "read": 0})
        group["read"] += node["bytes"]
    volumes = []
    for group in groups.values():
        try:
            used = shutil.disk_usage(group["path"]).used
        except OSError as exc:
            ctx.error(group["path"], "disk_usage: " + (exc.strerror or "error"))
            continue
        volumes.append(
            {
                "path": group["path"],
                "used_bytes": used,
                "read_bytes": group["read"],
                "unexplained_bytes": used - group["read"],
                "explained_bytes": 0,
            }
        )
    # A hold is subtracted only from the volume it lives on, and never below zero: a negative figure
    # is for what the scan over-counted, not for what a hold took away.
    explained = []  # type: List[Dict[str, Any]]
    explained_at = []  # type: List[Tuple[str, int, Optional[str]]]  # (volume path, bytes, where the hold lives)
    elsewhere = []  # type: List[Dict[str, Any]]
    for hold in holds or []:
        if not (hold.get("in_gap") and isinstance(hold.get("bytes"), int) and hold["bytes"] > 0):
            continue
        where = hold.get("path")
        volume = next((v for v in volumes if where and _same_pool(where, v["path"])), None)
        if volume is None:
            elsewhere.append({"kind": hold["kind"], "bytes": hold["bytes"], "path": where})
            continue
        part = min(hold["bytes"], volume["unexplained_bytes"] - volume["explained_bytes"])
        if part <= 0:  # the scan already over-counted this volume: nothing left to explain
            continue
        volume["explained_bytes"] += part
        explained.append({"kind": hold["kind"], "bytes": part, "volume": volume["path"]})
        explained_at.append((volume["path"], part, where))
    # What the roots miss, measured by measure_outside, comes off the same way and after the holds: a hold that
    # lives inside a missed folder (a Linux swap file in /) was already taken off, so it is not taken off twice.
    located = []  # type: List[Dict[str, Any]]
    by_volume = {v["path"]: v for v in (outside or {}).get("volumes", []) if isinstance(v, dict)}
    for volume in volumes:
        found = by_volume.get(volume["path"])
        volume["located_bytes"] = 0
        if not found or not found.get("bytes"):
            continue
        paths = [e["abs"] for e in found.get("entries", []) if e.get("abs")]
        twice = sum(part for vpath, part, at in explained_at if vpath == volume["path"] and at and any(_within(at, p) for p in paths))
        room = max(volume["unexplained_bytes"] - volume["explained_bytes"], 0)
        volume["located_bytes"] = min(max(found["bytes"] - twice, 0), room)
        for entry in found.get("entries", []):
            located.append({"path": entry["path"], "bytes": entry["bytes"], "complete": entry["complete"], "volume": volume["path"]})
    located.sort(key=lambda e: e["bytes"], reverse=True)
    explained_bytes = sum(v["explained_bytes"] for v in volumes)
    located_bytes = sum(v["located_bytes"] for v in volumes)
    raw = sum(v["unexplained_bytes"] for v in volumes)
    others = list((outside or {}).get("other_volumes", []))
    partial = bool(outside) and bool(outside.get("partial") or others)
    return {
        "label": LABEL_OUTSIDE if partial else LABEL_UNEXPLAINED,
        "partial": partial,
        "unexplained_bytes": raw - explained_bytes - located_bytes,
        "raw_unexplained_bytes": raw,
        "explained_bytes": explained_bytes,
        "explained_by": explained,
        "held_elsewhere": elsewhere,
        "outside_roots_bytes": located_bytes,
        "outside_roots": located[:OUTSIDE_LISTED],
        "outside_roots_complete": bool(outside) and bool(outside.get("complete")),
        "outside_roots_seconds": (outside or {}).get("seconds"),
        "outside_roots_notes": [v["note"] for v in (outside or {}).get("volumes", []) if isinstance(v, dict) and v.get("note")],
        "other_volumes": others[:OUTSIDE_LISTED],
        "used_bytes": sum(v["used_bytes"] for v in volumes),
        "read_bytes": sum(v["read_bytes"] for v in volumes),
        "volumes": volumes,
        "note": (
            "Volume used space minus what the scan read (raw_unexplained_bytes). When the roots do not cover the "
            "whole volume (label 'outside the scanned roots') that figure is, by definition, outside the roots: "
            "other users, /private, other volumes of the same APFS container (other_volumes: statvfs reports the "
            "whole container on each, so they cannot be sized), local snapshots and purgeable space. "
            "outside_roots lists the folders below the volume's mount point that no root contains, measured within "
            "a time budget (outside_roots_complete false = a lower bound). unexplained_bytes is what is left after "
            "subtracting the holds that system_holds measured on the same volume (explained_by; held_elsewhere "
            "lives on another volume and is not subtracted) and the measured outside_roots_bytes. volumes[] are "
            "before the subtraction. Negative means the scan counted more than the volume holds (basic mode "
            "counts APFS clones in full)."
        ),
    }


def _top(tree: Dict[str, Any], limit: int = TOP_N) -> List[Dict[str, Any]]:
    """Biggest leaves plus the loose-files "rest" of containers, so every byte appears once."""
    rows = []  # type: List[Dict[str, Any]]

    def add(node: Dict[str, Any], nbytes: int, kind: str) -> None:
        rows.append({"path": node["path"], "bytes": nbytes, "apparent": node["apparent"], "kind": kind})

    def visit(node: Dict[str, Any]) -> None:
        kids = node["children"]
        if not kids:
            if node["bytes"] > 0:
                add(node, node["bytes"], "folder")
            return
        rest = node["bytes"] - sum(k["bytes"] for k in kids)
        if rest >= REST_MIN_BYTES:
            add(node, rest, "rest")
        for kid in kids:
            visit(kid)

    for root in tree["children"]:
        visit(root)
    rows.sort(key=lambda r: r["bytes"], reverse=True)
    return rows[:limit]


def scan(roots: List[str], use_dua: bool, timeout: Optional[int] = None) -> dict:
    kept, dropped = _prepare_roots(roots)
    for item in dropped:
        log("root dropped: %s (%s)" % (item["path"], item["reason"]))
    dua = _make_dua(platform_info.check().get("dua"), timeout or DUA_TIMEOUT_S) if use_dua else None
    return _scan_all(kept, _Ctx(dua))


# --------------------------------------------------------------------------- snapshots


def _snapshot_result(tool: str, available: bool, items: list, error: Optional[str], note: str) -> Dict[str, Any]:
    return {"tool": tool, "available": available, "items": items, "count": len(items), "error": error, "note": note}


_SNAP_NOTE = "No tool reports snapshot sizes; the space they hold is inside the GAP."


def _snap_tmutil() -> Dict[str, Any]:
    rc, out, err = _run_cmd(["tmutil", "listlocalsnapshots", "/"])
    if rc is None or rc != 0:
        return _snapshot_result("tmutil", False, [], _first_line(err) or "tmutil failed", _SNAP_NOTE)
    items = []
    for line in out.splitlines():
        match = re.match(r"^\s*(com\.apple\.\S+)", line)
        if match:
            stamp = re.search(r"(\d{4}-\d{2}-\d{2}-\d{6})", match.group(1))
            items.append({"name": match.group(1), "date": stamp.group(1) if stamp else None})
    note = _SNAP_NOTE + " Deleting needs root and Full Disk Access: corecleaner only prints the command."
    return _snapshot_result("tmutil", True, items, None, note)


def _btrfs_mounts(text: str) -> List[str]:
    mounts = []  # type: List[str]
    for line in text.splitlines():
        parts = line.split(" ")
        if len(parts) >= 3 and parts[2] == "btrfs":
            mount = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), parts[1])
            if mount not in mounts:
                mounts.append(mount)
    return mounts[:8]


def _read_proc_mounts() -> str:
    try:
        with open("/proc/self/mounts", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _parse_btrfs_list(text: str, mount: str) -> List[Dict[str, Any]]:
    items = []
    for line in text.splitlines():
        match = re.match(r"^ID\s+(\d+)\s+gen\s+\d+.*?\bpath\s+(.+?)\s*$", line)
        if match:
            made = re.search(r"otime\s+(\S+\s+\S+)", line)
            items.append(
                {"mount": mount, "id": int(match.group(1)), "path": match.group(2), "created": made.group(1) if made else None}
            )
    return items


def _snap_btrfs() -> Dict[str, Any]:
    mounts = _btrfs_mounts(_read_proc_mounts())
    if not shutil.which("btrfs") or not mounts:
        return _snapshot_result("btrfs", False, [], None, "no btrfs filesystem or no btrfs tool; nothing to list")
    items = []  # type: List[Dict[str, Any]]
    errors = []
    for mount in mounts:
        rc, out, err = _run_cmd(["btrfs", "subvolume", "list", "-s", mount])
        if rc == 0:
            items.extend(_parse_btrfs_list(out, mount))
        else:
            errors.append("%s: %s" % (mount, _first_line(err) or "btrfs failed (root is usually required)"))
    return _snapshot_result("btrfs", True, items, "; ".join(errors) or None, _SNAP_NOTE)


def _parse_vss(text: str) -> List[Dict[str, Any]]:
    items = []  # type: List[Dict[str, Any]]
    for line in text.splitlines():
        volume = re.match(r"^\s*For volume:\s*(.+?)\s*$", line)
        if volume:
            items.append({"volume": volume.group(1)})
            continue
        size = re.match(r"^\s*(Used|Allocated|Maximum)\s+Shadow Copy Storage space:\s*([\d.,]+)\s*(\w+)", line)
        if size and items:
            try:
                value = int(round(_parse_number(size.group(2)) * _unit_factor(size.group(3), True)))
            except (ValueError, IndexError):
                continue
            items[-1][size.group(1).lower() + "_bytes"] = value
    return items


def _snap_vss() -> Dict[str, Any]:
    rc, out, err = _run_cmd(["vssadmin", "list", "shadowstorage"])
    if rc is None:
        return _snapshot_result("vssadmin", False, [], err, _SNAP_NOTE)
    if rc != 0:
        message = _first_line(out) or _first_line(err) or "vssadmin failed"
        return _snapshot_result("vssadmin", False, [], message + " (needs an elevated prompt)", _SNAP_NOTE)
    items = _parse_vss(out)
    error = None if items or not out.strip() else "no shadow storage found in the output (localized text?)"
    return _snapshot_result("vssadmin", True, items, error, _SNAP_NOTE)


def read_snapshots() -> Dict[str, Any]:
    kind = platform_info.os_kind()
    if kind == "macos":
        return _snap_tmutil()
    if kind == "linux":
        return _snap_btrfs()
    if kind == "windows":
        return _snap_vss()
    return _snapshot_result("none", False, [], None, "no snapshot reader for this OS")


# --------------------------------------------------------------------------- what the system holds

VM_VOLUME = "/System/Volumes/VM"
FINDER_TRASH_SCRIPT = 'tell application "Finder" to get physical size of every item of trash'
PS_PAGEFILE = (
    "Get-CimInstance Win32_PageFileUsage | Select-Object Name,AllocatedBaseSize,CurrentUsage | ConvertTo-Json -Compress"
)
FDA_TRASH_NOTE = (
    "Trash: not measurable without Full Disk Access "
    "(System Settings > Privacy & Security > Full Disk Access > add your terminal)"
)
_SWAPUSAGE_RE = re.compile(r"\b(total|used|free)\s*=\s*([\d.,]+)\s*([KMGT])", re.IGNORECASE)
_PROC_SWAP_RE = re.compile(r"^(.+?)\s+(file|partition)\s+(\d+)\s+(\d+)\s+(-?\d+)\s*$")


def _hold(kind: str, label: str, nbytes: Optional[int], in_gap: bool, note: str, action: str, **extra: Any) -> Dict[str, Any]:
    item = {
        "kind": kind,
        "label": label,
        "bytes": nbytes,
        "measured": nbytes is not None,
        "in_gap": bool(in_gap and nbytes is not None),
        "note": note,
        "action": action,
    }  # type: Dict[str, Any]
    item.update(extra)
    return item


def _outside(path: str, roots: List[str]) -> bool:
    """True when `path` is not under a scanned root, so the scan did not already count it."""
    return not any(_within(path, root) for root in roots)


def parse_swapusage(text: str) -> Dict[str, int]:
    """macOS `sysctl -n vm.swapusage` ("total = 12288.00M  used = 10773.25M  free = ...") to bytes."""
    result = {}  # type: Dict[str, int]
    for key, number, unit in _SWAPUSAGE_RE.findall(text):
        try:
            result[key.lower()] = int(round(_parse_number(number) * 1024 ** ("KMGT".index(unit.upper()) + 1)))
        except ValueError:
            continue
    return result


def parse_proc_swaps(text: str) -> List[Dict[str, Any]]:
    """Linux /proc/swaps rows: path, type (file|partition), size and used in bytes (the file counts KiB)."""
    items = []  # type: List[Dict[str, Any]]
    for line in text.splitlines():
        match = _PROC_SWAP_RE.match(line.strip())
        if match:
            path = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), match.group(1))
            items.append(
                {"path": path, "type": match.group(2), "size_bytes": int(match.group(3)) * 1024, "used_bytes": int(match.group(4)) * 1024}
            )
    return items


def parse_pagefile_json(text: str) -> List[Dict[str, Any]]:
    """Windows Get-CimInstance Win32_PageFileUsage as JSON (one object or a list; sizes are MB)."""
    data = json.loads(text)
    rows = data if isinstance(data, list) else [data]
    items = []  # type: List[Dict[str, Any]]
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("AllocatedBaseSize"), (int, float)):
            used = row.get("CurrentUsage")
            items.append(
                {
                    "path": str(row.get("Name") or "pagefile.sys"),
                    "size_bytes": int(row["AllocatedBaseSize"]) << 20,
                    "used_bytes": int(used) << 20 if isinstance(used, (int, float)) else None,
                }
            )
    return items


def _files_allocated(folder: str) -> Optional[int]:
    """Allocated bytes of the regular files directly inside `folder`; None when it cannot be listed."""
    total = 0
    try:
        with os.scandir(folder) as it:
            for entry in it:
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if statmod.S_ISREG(st.st_mode):
                    total += _allocated(st)
    except OSError:
        return None
    return total


def _swap_macos(roots: List[str]) -> List[Dict[str, Any]]:
    rc, out, _ = _run_cmd(["sysctl", "-n", "vm.swapusage"], QUICK_TIMEOUT_S)
    usage = parse_swapusage(out) if rc == 0 else {}
    on_disk = _files_allocated(VM_VOLUME)
    nbytes = on_disk if on_disk is not None else usage.get("total")
    if nbytes is None:
        return []
    source = "files in " + VM_VOLUME if on_disk is not None else "sysctl vm.swapusage total (estimate)"
    note = "Swap on disk: %s" % source
    if "used" in usage:
        note += "; in use now: %d bytes of %d" % (usage["used"], usage.get("total", 0))
    return [
        _hold(
            "swap", "Swap", nbytes, _outside(VM_VOLUME, roots), note,
            "Restart the Mac to release swap; closing heavy apps reduces it.",
            used_bytes=usage.get("used"), total_bytes=usage.get("total"), source=source,
            path=VM_VOLUME if on_disk is not None or os.path.exists(VM_VOLUME) else "/",
        )
    ]


def _read_proc_swaps() -> str:
    try:
        with open("/proc/swaps", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _swap_linux(roots: List[str]) -> List[Dict[str, Any]]:
    entries = parse_proc_swaps(_read_proc_swaps())
    if not entries:
        return []
    in_files = 0
    outside = True
    partitions = 0
    for entry in entries:
        if entry["type"] == "partition":
            partitions += entry["size_bytes"]
            continue
        try:
            in_files += _allocated(os.stat(entry["path"]))
        except OSError:
            in_files += entry["size_bytes"]
        outside = outside and _outside(entry["path"], roots)
    note = "Swap files take %d bytes on the volume; swap partitions (%d bytes) are separate partitions." % (in_files, partitions)
    return [
        _hold(
            "swap", "Swap", in_files, outside, note,
            "Restart to clear swap in use; closing memory-heavy apps reduces it. A swap file keeps its size until swapoff + resize.",
            partitions_bytes=partitions, used_bytes=sum(e["used_bytes"] for e in entries),
            path=next((e["path"] for e in entries if e["type"] != "partition"), None),
        )
    ]


def _swap_windows(roots: List[str]) -> List[Dict[str, Any]]:
    rc, out, _ = _run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_PAGEFILE], CMD_TIMEOUT_S)
    if rc != 0 or not out.strip():
        return []
    items = parse_pagefile_json(out)
    if not items:
        return []
    nbytes = sum(i["size_bytes"] for i in items)
    return [
        _hold(
            "swap", "Pagefile", nbytes, all(_outside(i["path"], roots) for i in items),
            "Windows pagefile allocated: %s" % ", ".join(i["path"] for i in items),
            "Restart to reset the pagefile; its size is set in System Properties > Advanced > Performance > Virtual memory.",
            used_bytes=sum(i["used_bytes"] or 0 for i in items), path=items[0]["path"],
        )
    ]


_SNAP_ACTION = {
    "macos": "macOS deletes them on its own (about 24 h, or sooner when space is needed). For the space now: "
             "`tmutil deletelocalsnapshots /` (no admin; the terminal may need Full Disk Access); corecleaner only prints it.",
    "linux": "Delete with `btrfs subvolume delete <path>` (root); corecleaner only prints it.",
    "windows": "Delete with `vssadmin delete shadows /for=C:` (elevated prompt); corecleaner only prints it.",
}


def _snapshots_hold(snapshots: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    count = snapshots.get("count") if isinstance(snapshots, dict) else None
    if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
        return []
    return [
        _hold(
            "snapshots", "Local snapshots", None, True,
            "%d local snapshot(s); no tool reports their size, it stays inside the GAP." % count,
            _SNAP_ACTION.get(platform_info.os_kind(), "Delete them with the OS tool; corecleaner only prints the command."),
            count=count,
        )
    ]


def _finder_trash_bytes() -> Tuple[Optional[int], bool]:
    """(bytes, lower_bound) of the Trash according to Finder; (None, False) when it cannot say.

    `physical size of trash` itself answers "missing value", the sizes of its items do not.
    """
    rc, out, _ = _run_cmd(["osascript", "-e", FINDER_TRASH_SCRIPT], FINDER_TIMEOUT_S)
    if rc != 0:
        return None, False
    total = 0
    missing = False
    for part in out.strip().split(","):
        token = part.strip()
        if not token:
            continue
        if token.isdigit():
            total += int(token)
        elif token.lower() == "missing value":
            missing = True
        else:
            return None, False
    return total, missing


def _trash_hold(roots: List[str], ask_finder: bool = False) -> List[Dict[str, Any]]:
    """macOS Trash that the scan cannot list (no Full Disk Access): say so, or ask Finder when `ask_finder`.

    Finder is opt-in (`--ask-finder`): the first question makes macOS ask the user whether the terminal may
    control Finder, and a read-only scan must not put a permission prompt on a screen nobody is watching.
    """
    if platform_info.os_kind() != "macos":
        return []
    trash = os.path.join(_home(), ".Trash")
    if not os.path.lexists(trash) or _outside(trash, roots):
        return []
    try:
        with os.scandir(trash) as it:
            next(it, None)
        return []  # readable: the scan already counted it
    except OSError as exc:
        if exc.errno not in (errno.EPERM, errno.EACCES):
            return []
    nbytes, lower_bound = _finder_trash_bytes() if ask_finder else (None, False)
    if nbytes is None:
        return [
            _hold(
                "trash", "Trash", None, True, FDA_TRASH_NOTE,
                "Grant Full Disk Access to your terminal and scan again, or scan again with --ask-finder "
                "(macOS may then ask once whether the terminal can control Finder), or open the Trash in "
                "Finder and empty it.",
                path=trash,
            )
        ]
    note = "Trash: not readable by the scan (no Full Disk Access); size taken from Finder"
    if lower_bound:
        note += " (some items had no size: at least this much)"
    return [
        _hold(
            "trash", "Trash", nbytes, True, note,
            "Empty the Trash in Finder to free it (moving files to the Trash frees nothing); corecleaner never empties it.",
            path=trash, measured_by="Finder (osascript)", lower_bound=lower_bound,
        )
    ]


def system_holds(
    roots: List[str], snapshots: Optional[Dict[str, Any]] = None, ask_finder: bool = False
) -> List[Dict[str, Any]]:
    """What the OS holds on disk that the folder scan cannot see; read-only, the action is for the human."""
    kind = platform_info.os_kind()
    swap = {"macos": _swap_macos, "linux": _swap_linux, "windows": _swap_windows}.get(kind)
    holds = []  # type: List[Dict[str, Any]]
    probes = [(lambda: swap(roots)) if swap else (lambda: []), lambda: _snapshots_hold(snapshots), lambda: _trash_hold(roots, ask_finder)]
    for probe in probes:
        try:
            holds.extend(probe())
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            log("system_holds probe failed: %s" % type(exc).__name__)
    return holds


# --------------------------------------------------------------------------- entry point


def _label(ctx: _Ctx) -> str:
    if ctx.dua is None:
        return "apparent (upper bound): allocated blocks, hardlinks once; APFS clones may look larger than they are"
    if ctx.dua.dedup:
        return "dua: allocated bytes, hardlinks once, APFS clones deduplicated (total exact, per-folder split may vary)"
    if ctx.apparent:
        return "apparent (upper bound): dua older than 2.43.0 cannot deduplicate APFS clones"
    return "dua: allocated bytes, hardlinks once (btrfs/XFS reflinks are not deduplicated; free space is the final measure)"


def _listed(items: List[str]) -> Dict[str, Any]:
    return {"count": len(items), "paths": items[:MAX_LISTED]}


def _resolve_timeout(args: Any) -> int:
    """Seconds per dua call: args.timeout, else env CORECLEANER_SCAN_TIMEOUT, else DUA_TIMEOUT_S."""
    for raw in (getattr(args, "timeout", None), os.environ.get(TIMEOUT_ENV)):
        if raw in (None, ""):
            continue
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
        log("ignoring invalid scan timeout %r" % (raw,))
    return DUA_TIMEOUT_S


def _resolve_max_seconds(args: Any) -> Optional[int]:
    """Wall-clock budget of the whole scan in seconds: args.max_seconds, else env CORECLEANER_SCAN_MAX_SECONDS, else none."""
    for raw in (getattr(args, "max_seconds", None), os.environ.get(MAX_SECONDS_ENV)):
        if raw in (None, ""):
            continue
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
        log("ignoring invalid scan time budget %r" % (raw,))
    return None


def _completeness(ctx: _Ctx) -> Tuple[bool, str]:
    """(complete, label prefix). A partial scan is a lower bound: unreadable entries and unmeasured roots are not in it."""
    parts = []
    if ctx.unreadable_total or ctx.warnings_total:
        parts.append(
            "%d unreadable entries" % ctx.unreadable_total if ctx.unreadable_total else "dua reported unreadable entries"
        )
    if ctx.unmeasured:
        parts.append("%d root(s) not measured" % len(ctx.unmeasured))
    if not parts:
        return True, ""
    return False, "partial scan (lower bound: %s): " % ", ".join(parts)


def run(args) -> dict:
    started = time.monotonic()
    requested = getattr(args, "roots", None)
    kept, dropped = _prepare_roots(list(requested) if requested else default_roots())
    if not kept:
        raise CorecleanerError(EXIT_ERROR, "no scannable root", dropped_roots=dropped)
    timeout = _resolve_timeout(args)
    max_seconds = _resolve_max_seconds(args)
    dua = None if getattr(args, "no_dua", False) else _make_dua(platform_info.check().get("dua"), timeout)

    def new_ctx(tool: Optional[_Dua]) -> _Ctx:
        made = _Ctx(tool)
        if max_seconds is not None and tool is not None:
            made.deadline = made.clock() + max_seconds
        return made

    ctx = new_ctx(dua)
    fallback = None
    try:
        tree = _scan_all(kept, ctx)
    except _Unusable as exc:
        fallback = str(exc)
        log(fallback + "; falling back to basic mode")
        ctx = new_ctx(None)
        tree = _scan_all(kept, ctx)
    snapshots = read_snapshots()
    holds = system_holds(kept, snapshots, ask_finder=bool(getattr(args, "ask_finder", False)))
    outside = None
    try:
        outside = measure_outside(kept, ctx)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:  # the map is complete without it
        log("measuring what the roots miss failed: %s" % type(exc).__name__)
    complete, prefix = _completeness(ctx)
    return {
        "tool": "dua" if ctx.dua else "basic",
        "exact": not ctx.apparent,
        "complete": complete,
        "label": prefix + _label(ctx),
        "fallback": fallback,
        "tree": tree,
        "read_bytes": tree["bytes"],
        "gap": _gap(tree["children"], ctx, holds, outside),
        "top": _top(tree),
        "snapshots": snapshots,
        "system_holds": holds,
        "skipped": {
            "cloud": _listed(ctx.cloud),
            "other_filesystem": _listed(ctx.other_fs),
            "placeholder_files": ctx.placeholder_files,
        },
        "errors": ctx.errors,
        "errors_total": ctx.errors_total,
        "warnings": ctx.warnings,
        "warnings_total": ctx.warnings_total,
        "unreadable_entries": ctx.unreadable_total,
        "roots": kept,
        "dropped_roots": dropped,
        "dua": {"path": ctx.dua.path, "version": ctx.dua.version, "dedup_apfs_clones": ctx.dua.dedup}
        if ctx.dua
        else None,
        "unmeasured_roots": ctx.unmeasured,
        "budget_spent": ctx.budget_spent,
        "timeout_s": timeout if ctx.dua else None,
        "max_seconds": max_seconds if ctx.dua else None,
        "timing": ctx.timings,
        "seconds": round(time.monotonic() - started, 1),
        "ts": now_iso(),
    }
