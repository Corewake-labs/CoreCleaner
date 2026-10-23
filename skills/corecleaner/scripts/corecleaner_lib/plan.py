"""Script-built plan with an integrity hash, and the guarded apply path. (T6; subcommand `plan`)

The agent never writes the plan: a script measures it, and `trash` accepts only ids from a plan
whose hash still matches (SPEC trava 2). The `trash` flow itself lives in trash.py.

run(args): args.candidates (file | None -> run inventory.inventory()).
  Builds the plan, writes state_subdir("plans")/plan-<file_stamp>.json (mode 0o600) and returns
  {"plan_file", "plan": plan_view(plan), "free_before", "sha256"}. The view carries ONLY sanitized
  names and numbers (SPEC trava 9); raw paths live in the plan file and never reach the agent.

build_plan(candidates, free_before=None) -> dict
  {"version": 1, "created", "free_before": int,
   "items": [{"id": "c3f9a1" (hash of the path, never a path), "group": 1|2|3, "category": "A".."L",
              "path": realpath, "display": sanitized name, "bytes", "inode", "mtime", "owner",
              "evidence": {compact ints/bools only}, "action": "trash"|"archive_then_trash"|
              "tool_command"|"list_only", "tool_command": str|None, "deny": str|None}],
   "summary": {...}, "sha256"}
  Groups: 1 sure junk, 2 quick decision, 3 user data / denied (shown only, always list_only).
  Optional evidence flag `user_data: true` forces group 3. Protected, cloud, placeholder, symlink,
  missing, live (process, mtime < 1 h, or the root's birthtime/ctime < 1 h: a tree restored with old
  mtimes) or kept-by-note paths stay in the plan as list_only with the reason in `deny`. Categories A, B, C
  also wait 45 days from the root's birthtime, not only from the mtime.
  A path cited by other files (a script, a CLAUDE.md, project code) is a live
  dependency: never group 1, it goes to group 2 with `reason` "live dependency: cited by N file(s)" and
  evidence.referenced_by (first 3 files, sanitized). If the dependency search did not finish
  (evidence.referenced_unverified), a path that would be group 1 goes to group 2 too; so does one a file
  may build in code (evidence.referenced_maybe: first 3 files), with `reason` "possibly cited: ...".
  A would-be group 1 repo that holds ignored data the archive does not carry (models, `.wrangler/state`:
  evidence.git.ignored_large, measured by inventory) goes to group 2 too, `reason` "ignored data not archived:
  N file(s), X", so the user sees what leaves without a copy.

plan_hash(plan) -> sha256 hex of the canonical JSON of the plan WITHOUT "sha256" and "mac".
write_plan adds "mac" (HMAC with the state-dir key, common.sign); load_plan(f) -> dict needs both: hash
mismatch, bad or missing mac, unreadable, loose file mode, bad shape or an id/display that does not
derive from the path -> exit 41. `plan --candidates F` accepts only an inventory file `inventory`
saved in the state dir (owner, mode, mac), never a hand-written one, and a tool_command is accepted
only when it is one `inventory` itself could have built for that path.
Both go stale: an inventory (`ts`) older than MAX_AGE_HOURS is refused by `plan --candidates`, a plan (`created`)
by `trash --apply`, with exit 42 and a message that says "re-run inventory" (stale_reason; a missing or unreadable
stamp is refused too). The `trash` dry run only warns.

Apply side: recheck_item (exit 42). The `trash` flow itself (ids, live check, archive, manifest) is trash.py.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import common, platform_info, safety
from .common import CorecleanerError

PLAN_VERSION = 1
ACTIONS = ("trash", "archive_then_trash", "tool_command", "list_only")
CATEGORIES = "ABCDEFGHIJKL"
OWNERS = ("claude", "codex", "tool", "user", "unknown")
LIVE_WINDOW_S = 3600  # mtime newer than this = live state (SPEC trava 7)
MAX_AGE_HOURS = 12  # a plan or an inventory older than this is refused: citations, keep notes and live processes go stale
FUTURE_SLACK_S = 300  # a stamp this far ahead of the clock cannot be trusted either
WALK_CAP = 200000  # directory entries visited per measure(); beyond it the result is partial
MTIME_EPS = 1e-3
MAX_TOOL_COMMAND = 400
_ID_RE = re.compile(r"[A-Za-z0-9]{1,32}")  # used with fullmatch: `$` would let a trailing newline through
CATEGORIES_SCANNED_INSIDE = "ABCDH"  # E (node_modules), F, G are regenerable and full of test keys; repos go to archive.py
_REPARSE_POINT = 0x400

GAIN_NOTE = (
    "Sizes are apparent (allocated blocks per path, an upper bound). Real gain = free space after "
    "minus free space before. It is usually smaller: APFS clones and hardlinks free blocks only "
    "when the last copy goes, local snapshots keep deleted space, and the Trash frees nothing "
    "until you empty it. Tool commands free space when the tool runs."
)


# ---------------------------------------------------------------- small helpers


def canonical(obj: Any) -> bytes:
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8", "surrogatepass")


def has_control(text: str) -> bool:
    """True for control, format (bidi overrides, zero width), surrogate, line/paragraph separators and
    variation selectors: exactly the characters safety.sanitize_name replaces."""
    return any(safety.is_unsafe_char(ch) for ch in text)


def _int(value: Any, default: int = 0) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _float(value: Any, default: float = 0.0) -> float:
    ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    return float(value) if ok and math.isfinite(value) else default


def _tilde(path: str) -> str:
    home = str(Path.home())
    if path == home:
        return "~"
    return "~" + path[len(home):] if path.startswith(home + os.sep) else path


def _link_like(st: os.stat_result) -> bool:
    attrs = getattr(st, "st_file_attributes", 0)
    return stat.S_ISLNK(st.st_mode) or bool(attrs & _REPARSE_POINT)


def _blocks(st: os.stat_result) -> int:
    blocks = getattr(st, "st_blocks", None)
    return blocks * 512 if blocks is not None else st.st_size


def measure(path: str, cap: int = WALK_CAP) -> Tuple[int, float, bool]:
    """(allocated bytes, newest mtime inside, partial). lstat only, symlinks never followed, one device.

    `newest` follows the inventory's rule: files and links only, Finder noise left out. A folder's mtime moves
    when Finder drops a .DS_Store in it, so counting either made every browsed folder "modified after the plan"."""
    from .inventory import is_noise  # lazy: plan is imported by modules inventory never needs

    st = os.lstat(path)
    total, partial = _blocks(st), False
    if not stat.S_ISDIR(st.st_mode) or _link_like(st):
        return total, st.st_mtime, partial
    newest = 0.0
    seen, stack = 0, [path]
    while stack:
        try:
            it = os.scandir(stack.pop())
        except OSError:
            partial = True
            continue
        with it:
            for entry in it:
                seen += 1
                if seen > cap:
                    return total, newest, True
                try:
                    est = entry.stat(follow_symlinks=False)
                except OSError:
                    partial = True
                    continue
                if not stat.S_ISDIR(est.st_mode) and not is_noise(entry.name):
                    newest = max(newest, est.st_mtime)
                total += _blocks(est)
                # DirEntry.stat() reports st_dev 0 on Windows: only a real, different device stops the descent.
                same_dev = not (est.st_dev and st.st_dev) or est.st_dev == st.st_dev
                if stat.S_ISDIR(est.st_mode) and same_dev and not _link_like(est):
                    stack.append(entry.path)
    return total, newest, partial


def tree_fingerprint(path: str, cap: int = WALK_CAP) -> Tuple[float, int, bool]:
    """(newest mtime, entry count, partial) of the tree with every `.git` directory left out.

    A repo is read by git while it is archived (the index may be rewritten); its working files must not
    move. Comparing two fingerprints around the archive proves nothing was edited meanwhile.
    """
    st = os.lstat(path)
    newest, count, partial = st.st_mtime, 0, False
    if not stat.S_ISDIR(st.st_mode) or _link_like(st):
        return newest, count, partial
    stack = [path]
    while stack:
        try:
            it = os.scandir(stack.pop())
        except OSError:
            partial = True
            continue
        with it:
            for entry in it:
                if entry.name == ".git":
                    continue
                count += 1
                if count > cap:
                    return newest, count, True
                try:
                    est = entry.stat(follow_symlinks=False)
                except OSError:
                    partial = True
                    continue
                newest = max(newest, est.st_mtime)
                same_dev = not (est.st_dev and st.st_dev) or est.st_dev == st.st_dev
                if stat.S_ISDIR(est.st_mode) and same_dev and not _link_like(est):
                    stack.append(entry.path)
    return newest, count, partial


def _is_empty_dir(path: str) -> bool:
    try:
        with os.scandir(path) as it:
            return next(it, None) is None
    except OSError:
        return False


def _short(text: Any, maxlen: int = 160) -> str:
    return safety.sanitize_name(str(text), maxlen)


def size_text(n: int) -> str:
    """Decimal size for people: 999 B, 1.5 MB, 2 GB."""
    value = float(max(n, 0))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1000 or unit == "TB":
            out = "%d" % value if unit == "B" else ("%.1f" % value).rstrip("0").rstrip(".")
            return "%s %s" % (out, unit)
        value /= 1000.0
    return "?"


def stale_reason(kind: str, stamp: Any, now: Optional[float] = None) -> Optional[str]:
    """Why a plan or an inventory (`kind`) stamped `stamp` (common.now_iso) is too old to act on, else None.

    The facts in it (files that cite a path, keep notes, processes working inside) are frozen on the day it was
    made. A stamp that is missing, unreadable or in the future is not proven fresh, so it is refused too."""
    redo = "re-run inventory" + ("" if kind == "inventory" else ", plan and ask")
    try:
        made = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return "the %s has no readable date: %s" % (kind, redo)
    age = (time.time() if now is None else now) - made
    if age < -FUTURE_SLACK_S:
        return "the %s is dated in the future: %s" % (kind, redo)
    if age > MAX_AGE_HOURS * 3600:
        return "the %s is %.1f h old (limit %d h): %s" % (kind, age / 3600, MAX_AGE_HOURS, redo)
    return None


# ---------------------------------------------------------------- hash and file


def plan_hash(plan: dict) -> str:
    body = {k: v for k, v in plan.items() if k not in ("sha256", "mac")}
    return hashlib.sha256(canonical(body)).hexdigest()


def write_plan(plan: dict) -> Path:
    """plan-<stamp>.json in the state dir, exclusive create, mode 0o600. ASCII JSON survives odd names."""
    folder = common.state_subdir("plans")
    signed = dict(plan)
    signed.pop("mac", None)
    signed["mac"] = common.sign(signed, "plan")
    data = (json.dumps(signed, ensure_ascii=True, indent=1) + "\n").encode("ascii")
    stamp = common.file_stamp()
    for n in range(100):
        target = folder / ("plan-%s%s.json" % (stamp, "" if n == 0 else "-%d" % n))
        try:
            fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        return target
    raise CorecleanerError(common.EXIT_ERROR, "could not create a unique plan file in the state directory")


def _tampered(why: str, f: Any) -> CorecleanerError:
    return CorecleanerError(common.EXIT_PLAN_TAMPERED, "plan rejected: " + why, plan=str(f))


def _virtual_ok(it: dict) -> bool:
    """A non-path item (tmutil snapshot, process) is legal only as shown-only: never actionable."""
    return it.get("virtual") is True and it.get("group") == 3 and it.get("action") == "list_only"


def _derived_ok(it: dict) -> bool:
    """id and display must come from the path: a forged item cannot show a harmless name for a real folder."""
    path = it["path"]
    digest = hashlib.sha256(path.encode("utf-8", "surrogatepass")).hexdigest()
    ident = it["id"]
    if not (ident[:1] == "c" and 7 <= len(ident) <= 33 and len(ident) % 2 == 1 and digest.startswith(ident[1:])):
        return False
    shown = path if it.get("virtual") is True else (os.path.basename(path.rstrip("/\\")) or path)
    return it["display"] == safety.sanitize_name(shown)


def _validate_shape(plan: Any, f: Any) -> None:
    if not isinstance(plan, dict) or plan.get("version") != PLAN_VERSION:
        raise _tampered("unsupported or missing version", f)
    items = plan.get("items")
    if not isinstance(items, list):
        raise _tampered("items is not a list", f)
    ids = set()
    for it in items:
        ok = (
            isinstance(it, dict)
            and isinstance(it.get("id"), str)
            and _ID_RE.fullmatch(it["id"])
            and it["id"] not in ids
            and isinstance(it.get("path"), str)
            and (os.path.isabs(it["path"]) or _virtual_ok(it))
            and it.get("group") in (1, 2, 3)
            and it.get("action") in ACTIONS
            and isinstance(it.get("display"), str)
            and isinstance(it.get("category"), str)
            and isinstance(it.get("bytes"), int)
            and isinstance(it.get("inode"), int)
            and isinstance(it.get("mtime"), (int, float))
            and not (it["group"] == 3 and it["action"] != "list_only")
            and not (it.get("deny") and it["action"] != "list_only")
            and not (it["action"] == "tool_command" and not it.get("tool_command"))
        )
        if ok and not _derived_ok(it):
            ok = False
        if not ok:
            raise _tampered("malformed item", f)
        ids.add(it["id"])


def load_plan(f: str) -> dict:
    try:
        st = os.lstat(f)
        if not stat.S_ISREG(st.st_mode):
            raise _tampered("not a regular file", f)
        if os.name == "posix" and (st.st_uid != os.geteuid() or st.st_mode & 0o022):
            raise _tampered("file is not private to the current user (owner or write bits)", f)
        data = json.loads(Path(f).read_bytes().decode("utf-8"))
    except CorecleanerError:
        raise
    except (OSError, ValueError):
        raise _tampered("unreadable or not valid JSON", f)
    stored = data.get("sha256") if isinstance(data, dict) else None
    if not isinstance(stored, str) or not hmac.compare_digest(stored, plan_hash(data)):
        raise _tampered("hash mismatch (edited after it was written)", f)
    body = {k: v for k, v in data.items() if k != "mac"}
    if not common.verify(body, data.get("mac"), "plan"):
        raise _tampered("not written by this tool (missing or wrong signature)", f)
    _validate_shape(data, f)
    return data


# ---------------------------------------------------------------- building


def _make_id(path: str, taken: Iterable[str]) -> str:
    digest = hashlib.sha256(path.encode("utf-8", "surrogatepass")).hexdigest()
    used = set(taken)
    for width in range(6, 33, 2):
        cand = "c" + digest[:width]
        if cand not in used:
            return cand
    raise CorecleanerError(common.EXIT_ERROR, "could not derive a unique plan id")


def _safety_deny(path: str, ev: dict) -> Optional[str]:
    try:
        prot, why = safety.is_protected(path)
        if prot or ev.get("protected"):
            return "protected: " + _short(why or ev.get("reason") or "deny list", 120)
        cloud, why = safety.is_cloud_or_placeholder(path)
        if cloud or ev.get("cloud"):
            return "cloud or placeholder: " + _short(why or ev.get("reason") or "synced folder", 120)
    except (OSError, ValueError) as exc:
        return "safety check failed: " + _short(getattr(exc, "strerror", None) or type(exc).__name__, 80)
    return None


# agent history, worktrees and clones hold work and context: offered only after this long untouched (owner rule)
MIN_IDLE_DAYS = 45
MIN_IDLE_CATS = frozenset({"A", "B", "C"})


def _stat_times(st: os.stat_result) -> Tuple[Optional[float], float]:
    """(birth, ctime) of the candidate ROOT: when the inode was created here, when it last changed.

    `cp -a`, `rsync -a`, unzip and a Time Machine restore keep the old mtimes of what they copy but make a
    new inode, so ctime says "arrived now" where the mtime says "idle for months". birth is None where the
    OS has no birthtime (Linux). Measured on macOS/APFS: setting an mtime older than the birthtime drags the
    birthtime back to it, so after `cp -a` only ctime still shows the arrival; birthtime is the weaker signal.
    A module-level function so tests can patch it: fixtures are created now and aged with utime, which no
    real clock can tell apart from a restore.
    """
    birth = getattr(st, "st_birthtime", None)
    ok = isinstance(birth, (int, float)) and not isinstance(birth, bool) and math.isfinite(birth) and birth > 0
    return (float(birth) if ok else None), float(st.st_ctime)


def _keep_deny(ev: dict, mtime: float, now: float, cat: str = "", born: Optional[float] = None,
               changed: float = 0.0) -> Optional[str]:
    """`born` and `changed` are the root's birthtime and ctime (see _stat_times).

    Live window: the newest of mtime, birthtime and ctime. Ctime is bumped by Spotlight xattrs, chmod and
    renames, so it can only keep an item out longer, never let one in. The 45-day floor takes birthtime
    only, because a ctime bump would push an old tree's floor out for good.
    """
    if ev.get("live_process"):
        return "live process uses it (live state, outside the plan)"
    if now - mtime < LIVE_WINDOW_S:
        return "modified less than 1 h ago (live state, outside the plan)"
    if now - max(born or 0.0, changed) < LIVE_WINDOW_S:
        return "arrived less than 1 h ago (live state, outside the plan)"
    if cat in MIN_IDLE_CATS and now - mtime < MIN_IDLE_DAYS * 86400:
        return "idle less than %d days (history, worktree or clone: kept)" % MIN_IDLE_DAYS
    if ev.get("local_only_note"):
        return "kept: a note in the repo says this branch is local-only (never push)"
    if cat in MIN_IDLE_CATS and born is not None and now - born < MIN_IDLE_DAYS * 86400:
        return "arrived less than %d days ago (history, worktree or clone: kept)" % MIN_IDLE_DAYS
    if ev.get("keep_note"):
        return "kept by a note in agent memory, CLAUDE.md, skills or settings"
    if ev.get("user_data"):
        return "user data: shown only"
    return None


def protected_inside_reason(cat: str, path: str) -> Optional[str]:
    """Why a directory must not go to the Trash because of WHAT IS INSIDE it, else None (fixed text, no names).

    Names like `.env` or `id_rsa` are protected at any depth; is_protected only sees the candidate's own path.
    A repo root is left to archive.py (its ignored secrets are kept in the archive); regenerable categories
    (E, F, G) are not scanned. Too big to scan = not proven = refused.
    """
    if cat not in CATEGORIES_SCANNED_INSIDE or not os.path.isdir(path) or os.path.lexists(os.path.join(path, ".git")):
        return None
    hits, cut = safety.find_protected_inside(path)
    if hits:
        return "holds %d file(s) with protected names (keys, .env, credentials): move them out first" % len(hits)
    if cut:
        return "too large to scan for protected names (keys, .env): not proven safe"
    return None


def _unproven_deny(ev: dict, measured: Optional[Tuple[int, float, bool]]) -> Optional[str]:
    size = ev.get("size")
    if isinstance(size, dict) and size.get("truncated"):
        return "too large to measure fully: cannot prove it idle"
    if ev.get("search_truncated"):
        return "the search for repos inside it hit its limit: cannot prove it clean"
    if measured is not None and measured[2]:
        return "could not read the whole tree: cannot prove it idle"
    return None


def _keeper_of(ev: dict) -> Tuple[Optional[dict], Optional[str]]:
    """(keeper record, deny). A duplicate is junk only while its keeper exists exactly as it was."""
    raw = ev.get("keeper")
    if raw is None:
        return None, None
    try:
        st = os.lstat(raw) if isinstance(raw, str) and os.path.isabs(raw) else None
    except OSError:
        st = None
    if st is None or not stat.S_ISREG(st.st_mode) or _link_like(st):
        return None, "the copy it duplicates is gone or not a plain file: not safe to remove"
    return {"path": raw, "inode": st.st_ino, "size": st.st_size, "mtime": st.st_mtime}, None


def _classify(cat: str, git: dict, tool_cmd: Optional[str], empty: bool,
              kind: Optional[str] = None) -> Tuple[int, str, Optional[str]]:
    """(group, action, deny)."""
    if cat == "K":
        return 3, "list_only", "forgotten process: list only"
    if cat == "L":  # heavy folders nobody else sees: size only, whatever the candidate says
        return 3, "list_only", "heavy folder: listed with its size only, never trashed by this tool"
    if cat not in CATEGORIES:
        return 3, "list_only", "unknown category"
    if tool_cmd and cat in ("F", "G", "J"):
        # Only a cache its manager refills is sure junk; a browser download (Playwright, Puppeteer) is not refilled
        return (1 if (cat == "F" and kind in SELF_REFILLING) else 2), "tool_command", None
    if cat == "J":
        return 3, "list_only", "held by the OS and no cleanup command is known"
    # E is node_modules: derived from a lockfile, so the project's git state says nothing about the folder itself.
    repo = bool(git.get("is_repo")) and cat != "E"
    at_risk = repo and (
        bool(git.get("dirty"))
        or _int(git.get("unpushed")) > 0
        or _int(git.get("stash")) > 0
        or not git.get("origin")
    )
    if at_risk:
        return 2, "archive_then_trash", None
    if empty or cat == "D" or (cat == "C" and repo):
        return 1, "trash", None
    return 2, "trash", None


def _ref_total(ev: dict) -> int:
    refs = ev.get("referenced_by")
    listed = len(refs) if isinstance(refs, list) else 0
    return max(listed, _int(ev.get("referenced_by_total")))


def _ref_unverified(ev: dict) -> bool:
    """True when the search for files citing this path did not run or did not finish."""
    notes = ev.get("unverified")
    return isinstance(notes, list) and any(isinstance(n, str) and n.startswith("referenced_by:") for n in notes)


def _ref_files(ev: dict, limit: int = 3, key: str = "referenced_by") -> List[str]:
    refs = ev.get(key)
    return [_short(_tilde(f), 160) for f in refs[:limit] if isinstance(f, str)] if isinstance(refs, list) else []


def _ignored_of(git: dict) -> Tuple[int, int]:
    """(files, bytes) of ignored data the archive would not carry, as inventory measured it."""
    big = git.get("ignored_large")
    return (_int(big.get("count")), _int(big.get("bytes"))) if isinstance(big, dict) else (0, 0)


def _compact_evidence(ev: dict, git: dict) -> dict:
    return {
        "git": {
            "is_repo": bool(git.get("is_repo")),
            "dirty": bool(git.get("dirty")),
            "unpushed": _int(git.get("unpushed")),
            "stash": _int(git.get("stash")),
            "has_origin": bool(git.get("origin")),
            "remote_checked": bool(git.get("remote_checked")),
            "ignored_large": dict(zip(("count", "bytes"), _ignored_of(git))),
        },
        "age_days": _int(ev.get("age_days")),
        "live_process": bool(ev.get("live_process")),
        "referenced_count": _ref_total(ev),
        "referenced_by": _ref_files(ev),
        "referenced_maybe": _ref_files(ev, key="referenced_maybe"),
        "referenced_unverified": _ref_unverified(ev),
        "keep_note": bool(ev.get("keep_note")),
        "local_only_note": bool(ev.get("local_only_note")),
    }


def _virtual_facts(cand: dict, ev: dict) -> List[str]:
    """What the user needs to recognise a process or snapshot, sanitized (never a raw string)."""
    facts = [safety.sanitize_name(cand.get("kind") or "virtual", 40)]
    if isinstance(ev.get("name"), str):
        facts.append(safety.sanitize_name(ev["name"], 30))
    up = ev.get("running_for_s")
    if isinstance(up, (int, float)) and not isinstance(up, bool) and up >= 0:
        facts.append("up %d min" % (up // 60))
    if isinstance(ev.get("cwd"), str):
        facts.append("cwd " + safety.sanitize_name(_tilde(ev["cwd"]), 90))
    return facts


# caches the package manager refills on the next install; browser downloads (playwright, puppeteer) need an explicit one.
# cache.homebrew is NOT here: `brew cleanup --prune=all` also removes old versions of installed formulae and other
# leftovers outside the cache (measured with `brew cleanup -n --prune=all`), so it is a decision, never sure junk.
SELF_REFILLING = frozenset({"cache.bun", "cache.go_mod", "cache.npm", "cache.pip", "cache.pnpm_store", "cache.uv"})


REFILL_REASON = "cited by %d file(s); its own tool rebuilds it"


def _dependency_group(group: int, action: str, kind: Any, ev: dict) -> Tuple[int, Optional[str]]:
    """(group, reason). A path other files cite is never "sure junk"; one whose search never finished is not proven unused."""
    cited = _ref_total(ev)
    if action == "tool_command" and kind in SELF_REFILLING:  # a citation is config, not content
        return group, (REFILL_REASON % cited) if cited else None
    if cited > 0:
        return max(group, 2), "live dependency: cited by %d file(s)" % cited
    if group == 1 and _ref_unverified(ev):  # a tool command too: a cache a project config points at is not "sure junk"
        if _ref_files(ev, 1, "referenced_maybe"):
            return 2, "possibly cited: a file may build this path in code, not proven unused"
        return 2, "dependency search incomplete: not proven unused"
    return group, None


def _build_item(cand: Any, now: float) -> Optional[dict]:
    if not isinstance(cand, dict):
        return None
    raw = cand.get("path")
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        return None
    ev = cand["evidence"] if isinstance(cand.get("evidence"), dict) else {}
    if cand.get("virtual") is True:  # tmutil snapshot, process: not a path, so never touched, only shown
        return {
            "id": "",
            "group": 3,
            "category": cand["category"] if isinstance(cand.get("category"), str) else "?",
            "path": raw,
            "display": safety.sanitize_name(raw),
            "bytes": max(_int(cand.get("bytes")), 0),
            "inode": 0,
            "mtime": _float(cand.get("mtime")),
            "owner": cand["owner"] if cand.get("owner") in OWNERS else "unknown",
            "evidence": _compact_evidence(ev, ev["git"] if isinstance(ev.get("git"), dict) else {}),
            "action": "list_only",
            "virtual": True,
            "tool_command": None,
            "keeper": None,
            "deny": "not a file: shown only (" + ", ".join(_virtual_facts(cand, ev)) + ")",
            "reason": None,
        }
    if not os.path.isabs(raw):
        return None
    git = ev["git"] if isinstance(ev.get("git"), dict) else {}
    cat = cand["category"] if isinstance(cand.get("category"), str) else "?"
    is_link = os.path.islink(raw)
    path = os.path.abspath(raw) if is_link else os.path.realpath(raw)
    try:
        st: Optional[os.stat_result] = os.lstat(path)
    except OSError:
        st = None
    cbytes, cmtime = _int(cand.get("bytes"), -1), _float(cand.get("mtime"))
    measured = measure(path) if (st is not None and not is_link and (cbytes < 0 or cmtime <= 0)) else None
    size = cbytes if cbytes >= 0 else (measured[0] if measured else 0)
    mtime = max(cmtime, st.st_mtime if st else 0.0, measured[1] if measured else 0.0)
    born, changed = _stat_times(st) if st is not None else (None, 0.0)  # the ROOT only: a tree walk would pay for nothing
    tool_cmd = ev.get("tool_command")
    bad_cmd = tool_cmd is not None and (
        not isinstance(tool_cmd, str) or not tool_cmd.strip() or len(tool_cmd) > MAX_TOOL_COMMAND or has_control(tool_cmd)
    )
    if isinstance(tool_cmd, str) and not bad_cmd:
        from . import inventory  # lazy: plan is imported by modules inventory never needs

        bad_cmd = tool_cmd not in inventory.clean_commands_for(path)  # never a free-form command from a file
    if bad_cmd or not isinstance(tool_cmd, str):
        tool_cmd = None
    keeper, keeper_deny = _keeper_of(ev)

    deny: Optional[str]
    if is_link:
        deny = "symlink: never trashed"
    elif st is None:
        deny = "missing"
    elif has_control(path):
        deny = "path contains control characters"
    else:
        deny = (
            _safety_deny(path, ev)
            or _keep_deny(ev, mtime, now, cat, born, changed)
            or _unproven_deny(ev, measured)
            or keeper_deny
            or protected_inside_reason(cat, path)
        )
    if deny is None and bad_cmd:
        deny = "tool command rejected (not a command this tool builds for that path)"
    if deny is None and cand.get("action") == "list_only" and not tool_cmd and cat not in ("J", "K", "L"):  # J, K, L say why below
        deny = "listed only: inventory found no safe action for it (no cleanup command; pick it by hand)"
    group, action = 3, "list_only"
    reason: Optional[str] = None
    if deny is None:
        group, action, deny = _classify(cat, git, tool_cmd, _is_empty_dir(path), cand.get("kind"))
    if deny is None:
        group, reason = _dependency_group(group, action, cand.get("kind"), ev)
        files, nbytes = _ignored_of(git)
        if group == 1 and action == "trash" and files > 0:
            # "sure junk" means nothing is lost; ignored models or local state are not in git and not in the archive
            group, reason = 2, "ignored data not archived: %d file(s), %s" % (files, size_text(nbytes))
    return {
        "id": "",
        "group": group,
        "category": cat,
        "path": path,
        "display": safety.sanitize_name(os.path.basename(path.rstrip("/\\")) or path),
        "bytes": size,
        "inode": st.st_ino if st else 0,
        "mtime": mtime,
        "owner": cand["owner"] if cand.get("owner") in OWNERS else "unknown",
        "evidence": _compact_evidence(ev, git),
        "action": action,
        "tool_command": tool_cmd if action == "tool_command" else None,
        "keeper": keeper,
        "deny": deny,
        "reason": reason,
    }


def _demote_nested(items: List[dict]) -> None:
    movable = {i["path"] for i in items if i["action"] in ("trash", "archive_then_trash")}
    for it in items:
        if it["path"] not in movable:
            continue
        parent = os.path.dirname(it["path"])
        while parent and parent != os.path.dirname(parent):
            if parent in movable:
                it.update(group=3, action="list_only", deny="nested inside another candidate; goes with it")
                break
            parent = os.path.dirname(parent)


def _summary(items: List[dict], skipped: int) -> dict:
    gb = {"1": 0, "2": 0, "3": 0}
    gc = {"1": 0, "2": 0, "3": 0}
    for it in items:
        gb[str(it["group"])] += it["bytes"]
        gc[str(it["group"])] += 1
    return {
        "group_bytes": gb,
        "group_counts": gc,
        "actionable_bytes": gb["1"] + gb["2"],
        "skipped_invalid": skipped,
        "expected_gain_note": GAIN_NOTE,
    }


def build_plan(candidates: List[dict], free_before: Optional[int] = None) -> dict:
    now = time.time()
    items: List[dict] = []
    seen = set()
    skipped = 0
    for cand in candidates:
        item = _build_item(cand, now)
        if item is None:
            skipped += 1
        elif item["path"] not in seen:
            seen.add(item["path"])
            items.append(item)
    items.sort(key=lambda i: i["path"])
    taken: List[str] = []
    for it in items:
        it["id"] = _make_id(it["path"], taken)
        taken.append(it["id"])
    _demote_nested(items)
    items.sort(key=lambda i: (i["group"], -i["bytes"], i["path"]))
    if free_before is None:
        free_before = _int(platform_info.free()["free_bytes"])
    plan = {
        "version": PLAN_VERSION,
        "created": common.now_iso(),
        "free_before": free_before,
        "items": items,
        "summary": _summary(items, skipped),
    }
    plan["sha256"] = plan_hash(plan)
    return plan


def plan_view(plan: dict) -> dict:
    """What the agent may see: sanitized names and numbers, never a raw path or free-form string."""
    keys = ("id", "group", "category", "display", "bytes", "owner", "action", "tool_command", "deny", "reason")
    rows = []
    for it in plan["items"]:
        row = {k: it.get(k) for k in keys}
        row["display"] = safety.sanitize_name(it["display"])
        row["path_display"] = safety.sanitize_name(_tilde(it["path"]), 120)
        row["evidence"] = it.get("evidence")
        rows.append(row)
    return {
        "version": plan["version"],
        "created": plan["created"],
        "free_before": plan["free_before"],
        "summary": plan["summary"],
        "items": rows,
        "sha256": plan["sha256"],
    }


def _reject_candidates(why: str) -> CorecleanerError:
    return CorecleanerError(common.EXIT_PLAN_TAMPERED, "candidates rejected: " + why)


def _read_candidates(src: str) -> List[dict]:
    """Only the file `inventory` saved: in the state dir, ours, private, signed. Never a hand-written list."""
    try:
        st = os.lstat(src)
        folder = os.path.realpath(str(common.state_subdir("inventories")))
        inside = os.path.dirname(os.path.realpath(src)) == folder
        data = json.loads(Path(src).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CorecleanerError(common.EXIT_USAGE, "cannot read candidates file: " + type(exc).__name__)
    if not stat.S_ISREG(st.st_mode) or not inside:
        raise _reject_candidates("not a file saved by `inventory` in the state directory")
    if os.name == "posix" and (st.st_uid != os.geteuid() or st.st_mode & 0o022):
        raise _reject_candidates("file is not private to the current user")
    if not isinstance(data, dict) or not common.verify({k: v for k, v in data.items() if k != "mac"}, data.get("mac"), "inventory"):
        raise _reject_candidates("missing or wrong signature: only `inventory` output is accepted")
    old = stale_reason("inventory", data.get("ts"))
    if old:
        raise CorecleanerError(common.EXIT_STATE_CHANGED, "candidates rejected: " + old)
    data = data.get("candidates")
    if not isinstance(data, list):
        raise CorecleanerError(common.EXIT_USAGE, "candidates file must be a list or {\"candidates\": [...]}")
    return data


def run(args) -> dict:
    src = getattr(args, "candidates", None)
    if src:
        candidates = _read_candidates(src)
    else:
        from . import inventory

        candidates = inventory.inventory()
    plan = build_plan(candidates)
    target = write_plan(plan)
    return {
        "plan_file": str(target),
        "plan": plan_view(plan),
        "free_before": plan["free_before"],
        "sha256": plan["sha256"],
    }


# ---------------------------------------------------------------- apply side: re-check (the flow lives in trash.py)


def recheck_item(item: dict) -> dict:
    """Exit 42 unless the item is exactly what the plan measured. Returns {newest_mtime, partial}."""
    path = item["path"]

    def fail(why: str) -> CorecleanerError:
        return CorecleanerError(common.EXIT_STATE_CHANGED, "changed since the plan: " + why, id=item["id"])

    if has_control(path):
        raise fail("name contains control characters")
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise fail("no longer exists")
    except OSError as exc:
        raise fail("cannot stat (%s)" % (exc.strerror or "error"))
    if _link_like(st):
        raise fail("is now a symlink or junction")
    if os.path.normcase(os.path.realpath(path)) != os.path.normcase(path):
        raise fail("realpath differs (a parent is now a symlink)")
    if item.get("inode") and st.st_ino != item["inode"]:
        raise fail("replaced (inode differs)")
    _, newest, partial = measure(path)
    if newest > item["mtime"] + MTIME_EPS:
        raise fail("modified after the plan")
    return {"newest_mtime": newest, "partial": partial}
