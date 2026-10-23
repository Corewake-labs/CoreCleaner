"""Deny list, path normalization, name sanitization, cloud/placeholder detection. (T2)

No subcommand: trash, plan, inventory and scan import this. Last wall against a fooled agent, so
it fails closed: any doubt (cannot resolve, cannot parse) means protected.

Deny list file: ../references/never-touch.txt (grammar in its header; this is its only parser).
Sections [all] + the current OS section. Modes: `tree` (path, descendants, parents), `node`
(path and parents, descendants allowed), `name` (any path component matches, fnmatch).

load_never_touch() -> list[dict]
  Parse the file for the current OS. One dict per rule: {"mode": "tree"|"node"|"name",
  "pattern": str (after ~ / $VAR / %VAR% expansion, '/' separators), "raw": str, "section": str}.
  Unset or empty environment variable -> rule skipped. Malformed line or missing file ->
  CorecleanerError (EXIT_ERROR), never "no rules". A `~` rule yields one dict per home (HOME and,
  on POSIX, the passwd home, so `HOME=/tmp/x corecleaner ...` cannot relocate the protection).
  Glob characters inside an expanded value are escaped ([*] [?] [[]): only the file's own text globs.

normalize(path) -> str
  Canonical comparison form: realpath (symlinks resolved; a non-existent tail is kept literally),
  Unicode NFC, '/' separators, no trailing slash, casefold when the filesystem is
  case-insensitive (platform_info.is_case_insensitive), Windows: 8.3 short names expanded and
  the `\\\\?\\` prefix stripped, junctions resolved, trailing dots/spaces dropped.

is_protected(path) -> (bool, reason)
  True when normalize(path) hits a rule in either direction (the path is protected, is inside a
  protected tree, or is a parent of a protected path), or when path resolves through a symlink
  into one. `reason` names the rule, e.g. "tree ~/.ssh". Also refuses, in code and independent of
  the file: HOME, filesystem roots and mount points, every parent of them, and the corecleaner state
  dir (computed without creating it). Both the realpath form and the lexical form are checked.

sanitize_name(s, maxlen=80) -> str
  Name safe to show to an agent: control characters (incl. tab, CR, LF, ESC, bidi overrides and
  other invisible format characters) replaced, runs collapsed, truncated to maxlen with a marker.
  File names are DATA, never instructions. mark_as_data(s, maxlen=80) -> str additionally wraps
  the result as one JSON string literal for embedding in free text.

is_cloud_or_placeholder(path) -> (bool, reason)
  True for synced folders (iCloud, OneDrive, Dropbox, Google Drive, Box...) and dataless
  placeholders (macOS st_flags SF_DATALESS 0x40000000; Windows st_file_attributes
  FILE_ATTRIBUTE_RECALL_ON_OPEN 0x40000 / RECALL_ON_DATA_ACCESS; allocated blocks << size).
  Such paths are list-only: never planned, never trashed. Use lstat; never open or read them.
  A path under a known sync root is decided from the string alone, with no filesystem access.
"""

from __future__ import annotations

import errno
import fnmatch
import json
import os
import plistlib
import re
import stat as stat_mod
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple

from .common import EXIT_ERROR, STATE_ENV, CorecleanerError

NEVER_TOUCH_FILE = Path(__file__).resolve().parents[2] / "references" / "never-touch.txt"

_SECTIONS = ("all", "macos", "linux", "windows")
_MODES = ("tree", "node", "name")
_SECTION_RE = re.compile(r"^\[(\w+)\]$")
_ANCHOR_RE = re.compile(r"^(~|<root>|\$\{?\w+\}?|%[^%]+%|/|[A-Za-z]:/)")
_VAR_RE = re.compile(r"^(?:\$\{(\w+)\}|\$(\w+)|%([^%]+)%)")
_GLOB_CHARS = ("*", "?", "[")

# Placeholder detection (lstat only).
SF_DATALESS = 0x40000000  # macOS st_flags: content lives in the cloud
UF_COMPRESSED = 0x20  # macOS st_flags: transparent compression, st_blocks is not the size
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
_SPARSE_MIN_SIZE = 1 << 20
_SPARSE_RATIO = 64  # allocated*64 <= size: far below. Compressed/sparse files can trip it (list-only, safe).

# Home-relative sync roots ('*' globs one component). Same families as never-touch.txt.
_CLOUD_HOME_REL = (
    ("iCloud Drive", "Library/Mobile Documents"),
    ("macOS File Provider (CloudStorage)", "Library/CloudStorage"),
    ("Dropbox", "Dropbox"),
    ("Dropbox", "Dropbox (*)"),
    ("OneDrive", "OneDrive*"),
    ("Google Drive", "Google Drive"),
    ("Google Drive", "GoogleDrive"),
    ("Box", "Box"),
    ("Box", "Box Sync"),
    ("iCloud Drive", "iCloud Drive"),
    ("iCloud Drive", "iCloudDrive"),
    ("iCloud Photos", "Pictures/iCloud Photos"),
    ("pCloud", "pCloudDrive"),
    ("MEGA", "MEGA"),
    ("Nextcloud", "Nextcloud"),
    ("ownCloud", "ownCloud"),
    ("Creative Cloud", "Creative Cloud Files*"),
)
_CLOUD_ABS = (("Google Drive (volume)", "/Volumes/GoogleDrive*"),)
# Google Drive for desktop on Windows mounts a virtual drive whose first folder is one of these.
_GDRIVE_WINDOWS_ROOTS = frozenset(
    ("my drive", "meu drive", "mi unidad", "shared drives", "drives compartilhados")
)

# Invisible or smuggling-prone characters that are not in a Cc/Cf category. The variation selectors
# (FE00-FE0F, E0100-E01EF) draw nothing on their own: each one is a hidden bit a name can carry.
_INVISIBLE_CP = frozenset(
    (0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x2800, 0x3164, 0xFFA0)
    + tuple(range(0xFE00, 0xFE10))
    + tuple(range(0xE0100, 0xE01F0))
)
_TRUNCATION_MARKER = "..."
_REPLACEMENT = "?"

_CACHE: Dict[str, Any] = {}


# ----------------------------------------------------------------------------- platform bits


def _os_kind() -> str:
    if sys.platform == "darwin":
        return "macos"
    if sys.platform == "win32":
        return "windows"
    return "linux"


def _is_windows() -> bool:
    return os.name == "nt"


def _reset_caches() -> None:
    """Drop every cached rule set (tests, or after the environment changed on purpose)."""
    _CACHE.clear()


def _case_insensitive(real: str) -> bool:
    """Filesystem holding `real`. Any doubt answers True: folding case only adds refusals."""
    probe = real
    while probe and not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    try:
        from . import platform_info  # lazy: no import cycle, and a stub there must not break us

        return bool(platform_info.is_case_insensitive(probe))
    except Exception:
        return True


# ----------------------------------------------------------------------------- canonical form


def _as_text(path: Any) -> str:
    text = os.fspath(path)
    if isinstance(text, bytes):
        text = os.fsdecode(text)
    if not text or "\x00" in text:
        raise ValueError("empty path or NUL byte")
    return text


def _fold(text: str) -> str:
    """Casefold, back to NFC (full case folding can decompose, e.g. U+0390). Input is already NFC."""
    return unicodedata.normalize("NFC", text.casefold())


_EXT_UNC_RE = re.compile(r"^[\\/]{2}[?.][\\/]UNC[\\/]", re.IGNORECASE)
_EXT_RE = re.compile(r"^[\\/]{2}[?.][\\/]")
_DRIVE_RE = re.compile(r"^([A-Za-z]:)(?:/|$)")


def _strip_extended(p: str) -> str:
    """`\\\\?\\C:\\x` -> `C:\\x`, `\\\\?\\UNC\\srv\\share` -> `\\\\srv\\share`."""
    m = _EXT_UNC_RE.match(p)
    if m:
        return "\\\\" + p[m.end():]
    m = _EXT_RE.match(p)
    return p[m.end():] if m else p


def _split_anchor(p: str, windows: bool) -> Tuple[str, str]:
    """Return (anchor, rest). Anchor is '/', 'C:/', '//server/share/' or '' (relative/unknown)."""
    if windows:
        m = _DRIVE_RE.match(p)
        if m:
            return m.group(1) + "/", p[len(m.group(0)):]
        if p.startswith("//"):
            bits = p[2:].split("/", 2)
            server, share = bits[0], (bits[1] if len(bits) > 1 else "")
            return "//%s/%s/" % (server, share), (bits[2] if len(bits) > 2 else "")
    if p.startswith("/"):
        return "/", p
    return "", p


def _canon_parts(p: str, windows: bool, expand_short=None) -> Tuple[str, Tuple[str, ...]]:
    """(anchor, components): NFC, '/' separators, no '.', '..', empty or (Windows) padded names."""
    if windows:
        p = _strip_extended(p)
        if expand_short is not None:
            p = expand_short(p)
        p = p.replace("\\", "/")
    p = unicodedata.normalize("NFC", p)
    anchor, rest = _split_anchor(p, windows)
    comps: List[str] = []
    for comp in rest.split("/"):
        if windows and comp not in (".", ".."):
            comp = comp.rstrip(" .")  # Win32 drops trailing dots and spaces: ".ssh." is ".ssh"
        if comp in ("", "."):
            continue
        if comp == "..":
            if comps:
                comps.pop()
            continue
        comps.append(comp)
    return anchor, tuple(comps)


def _join(anchor: str, comps: Tuple[str, ...]) -> str:
    return anchor + "/".join(comps)


def _expand_short(p: str) -> str:
    """Windows: expand 8.3 names in the existing part of `p` (GetLongPathNameW); tail kept as is."""
    import ctypes

    head, tail = p, []
    while head and not os.path.exists(head):
        up, name = os.path.split(head)
        if not name or up == head:
            break
        tail.insert(0, name)
        head = up
    if not head:
        return p
    buf = ctypes.create_unicode_buffer(32768)
    n = ctypes.windll.kernel32.GetLongPathNameW("\\\\?\\" + head, buf, 32768)  # type: ignore[attr-defined]
    longhead = _strip_extended(buf.value) if 0 < n < 32768 else head
    return os.path.join(longhead, *tail) if tail else longhead


def _forms(text: str, windows: bool) -> Tuple[str, List[Tuple[str, Tuple[str, ...]]]]:
    """(realpath string, distinct canonical forms): realpath first, then the lexical spelling."""
    expand = _expand_short if windows else None
    real = os.path.realpath(text)
    candidates = [real, os.path.abspath(text)]
    if text.startswith("~"):  # an unexpanded "~/.ssh" is a doubt, so check what it would mean too
        user = os.path.expanduser(text)
        if user != text:
            candidates += [os.path.realpath(user), os.path.abspath(user)]
    forms: List[Tuple[str, Tuple[str, ...]]] = []
    for cand in candidates:
        form = _canon_parts(cand, windows, expand)
        if not form[0]:
            raise ValueError("unrecognized path form")
        if form not in forms:
            forms.append(form)
    return real, forms


def normalize(path: Any) -> str:
    """Canonical comparison form (see module docstring). Raises on a path it cannot resolve."""
    text = _as_text(path)
    windows = _is_windows()
    real = os.path.realpath(text)
    anchor, comps = _canon_parts(real, windows, _expand_short if windows else None)
    if windows or _case_insensitive(real):
        anchor, comps = _fold(anchor), tuple(_fold(c) for c in comps)
    return _join(anchor, comps)


# ----------------------------------------------------------------------------- deny list


def _bad_line(no: int, why: str) -> CorecleanerError:
    return CorecleanerError(
        EXIT_ERROR, "never-touch.txt line %d: %s" % (no, why), file=str(NEVER_TOUCH_FILE), line=no
    )


def _parse(text: str) -> List[Tuple[str, str, str, int]]:
    """Strict parse of the grammar in the file header -> [(section, mode, raw pattern, line)]."""
    section: Optional[str] = None
    rules: List[Tuple[str, str, str, int]] = []
    for no, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        head = _SECTION_RE.match(line)
        if head:
            if head.group(1) not in _SECTIONS:
                raise _bad_line(no, "unknown section " + line)
            section = head.group(1)
            continue
        if section is None:
            raise _bad_line(no, "rule before any [section]")
        mode, sep, pattern = line.partition(" ")
        if mode not in _MODES or not sep:
            raise _bad_line(no, "unknown mode or missing pattern")
        if not pattern or pattern != pattern.strip():
            raise _bad_line(no, "empty pattern or stray whitespace")
        if "\\" in pattern:
            raise _bad_line(no, "use '/' only")
        if mode == "name":
            if "/" in pattern:
                raise _bad_line(no, "a name pattern has no '/'")
        else:
            if not _ANCHOR_RE.match(pattern):
                raise _bad_line(no, "pattern must start with ~, <root>, $VAR, %VAR%, / or a drive")
            if pattern.startswith("<root>") and (pattern != "<root>" or mode != "node"):
                raise _bad_line(no, "<root> is node mode only and stands alone")
            if pattern.startswith("~") and pattern != "~" and not pattern.startswith("~/"):
                raise _bad_line(no, "only ~ and ~/ are supported")
        rules.append((section, mode, pattern, no))
    return rules


def _lit(value: str) -> str:
    """Escape fnmatch characters in an expanded value so a path like /a[b]c stays literal."""
    return re.sub(r"([*?\[])", r"[\1]", value)


def _homes() -> List[str]:
    home = os.path.expanduser("~")
    if not home or home == "~":
        raise CorecleanerError(EXIT_ERROR, "cannot determine the home directory")
    homes = [home]
    if os.name == "posix":
        try:
            import pwd

            real = pwd.getpwuid(os.getuid()).pw_dir
        except (ImportError, KeyError, OSError):
            real = ""
        if real and os.path.realpath(real) != os.path.realpath(home):
            homes.append(real)
    return homes


def _expand(raw: str, homes: List[str], windows: bool) -> List[str]:
    if raw == "<root>":
        return [raw]
    if raw == "~" or raw.startswith("~/"):
        return [_lit(h.replace("\\", "/") if windows else h) + raw[1:] for h in homes]
    m = _VAR_RE.match(raw)
    if m:
        value = os.environ.get(next(g for g in m.groups() if g))
        if not value:  # unset or empty: skip, an empty value would expand to the filesystem root
            return []
        return [_lit(value.replace("\\", "/") if windows else value) + raw[m.end():]]
    return [raw]


def _load(kind: str) -> Tuple[List[dict], Set[str]]:
    """(rules for `kind`, names of every environment variable the file references)."""
    try:
        text = NEVER_TOUCH_FILE.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise CorecleanerError(
            EXIT_ERROR, "cannot read the never-touch list: " + type(exc).__name__, file=str(NEVER_TOUCH_FILE)
        )
    parsed = _parse(text)
    homes = _homes()
    rules: List[dict] = []
    names: Set[str] = set()
    for section, mode, raw, _no in parsed:
        match = _VAR_RE.match(raw) if mode != "name" else None
        if match:
            names.add(next(g for g in match.groups() if g))
        if section not in ("all", kind):
            continue
        patterns = [raw] if mode == "name" else _expand(raw, homes, kind == "windows")
        for pattern in patterns:
            rules.append({"mode": mode, "pattern": pattern, "raw": raw, "section": section})
    return rules, names


def load_never_touch() -> List[dict]:
    return _load(_os_kind())[0]


class _Rule(NamedTuple):
    mode: str
    raw: str
    anchor: str
    parts: Tuple[str, ...]
    root: bool = False


def _has_glob(part: str) -> bool:
    return any(ch in part for ch in _GLOB_CHARS)


def _pattern_variants(pattern: str, windows: bool) -> List[Tuple[str, Tuple[str, ...]]]:
    """Lexical form, plus the form with the glob-free prefix resolved through symlinks."""
    anchor, comps = _canon_parts(pattern, windows)
    variants = [(anchor, comps)]
    cut = next((i for i, c in enumerate(comps) if _has_glob(c)), len(comps))
    try:
        real = os.path.realpath(_join(anchor, comps[:cut]))
        r_anchor, r_comps = _canon_parts(real, windows, _expand_short if windows else None)
        resolved = (r_anchor, r_comps + comps[cut:])
        if r_anchor and resolved != variants[0]:
            variants.append(resolved)
    except (OSError, ValueError):
        pass
    return variants


def _compile(items: List[dict], fold: bool, windows: bool) -> List[_Rule]:
    def prep(text: str) -> str:
        return _fold(text) if fold else text

    out: List[_Rule] = []
    for item in items:
        mode, pattern, raw = item["mode"], item["pattern"], item["raw"]
        if mode == "name":
            out.append(_Rule("name", raw, "", (prep(unicodedata.normalize("NFC", pattern)),)))
        elif pattern == "<root>":
            out.append(_Rule("node", raw, "", (), True))
        else:
            for anchor, parts in _pattern_variants(pattern, windows):
                out.append(_Rule(mode, raw, prep(anchor), tuple(prep(p) for p in parts)))
    return out


def _state_dir_path() -> Path:
    """Where common.state_dir() lives, without creating it (a scan must not write)."""
    override = os.environ.get(STATE_ENV)
    if override:
        return Path(override).expanduser()
    try:
        if sys.platform == "win32":
            base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
            return Path(base) / "corecleaner"
        return Path.home() / ".corecleaner"
    except RuntimeError as exc:
        raise CorecleanerError(EXIT_ERROR, "cannot determine the state directory: " + str(exc))


def _code_rules(homes: List[str]) -> List[dict]:
    """Protection that must not depend on the file: roots, HOME, the state dir."""

    def item(mode: str, pattern: str, raw: str) -> dict:
        return {"mode": mode, "pattern": pattern, "raw": raw, "section": "code"}

    items = [item("node", "<root>", "<root>")]
    items += [item("node", _lit(h), "HOME") for h in homes]
    items.append(item("tree", _lit(str(_state_dir_path())), "state dir"))
    # Archives of dirty repos can be the only copy of that work: never a Trash candidate.
    items += [item("tree", _lit(os.path.join(h, "corecleaner-archive")), "archive dir") for h in homes]
    return items


_ENV_ALWAYS = ("HOME", "USERPROFILE", "LOCALAPPDATA", STATE_ENV)


def _env_values(names: List[str]) -> Tuple[Optional[str], ...]:
    return tuple(os.environ.get(n) for n in names)


def _rules_for(fold: bool) -> List[_Rule]:
    """Compiled rules (file + code), cached until the file or a referenced variable changes."""
    kind = _os_kind()
    try:
        st = NEVER_TOUCH_FILE.stat()
    except OSError as exc:
        raise CorecleanerError(
            EXIT_ERROR, "cannot read the never-touch list: " + type(exc).__name__, file=str(NEVER_TOUCH_FILE)
        )
    sig = (str(NEVER_TOUCH_FILE), st.st_mtime_ns, st.st_size, kind)
    entry = _CACHE.get("rules")
    if entry and entry["sig"] == sig and entry["env"] == _env_values(entry["vars"]):
        return entry["by_fold"][fold or _is_windows()]
    items, names = _load(kind)
    items = items + _code_rules(_homes())
    windows = _is_windows()
    var_names = sorted(names | set(_ENV_ALWAYS))
    _CACHE["rules"] = {
        "sig": sig,
        "vars": var_names,
        "env": _env_values(var_names),
        "by_fold": {f: _compile(items, f or windows, windows) for f in (False, True)},
    }
    return _CACHE["rules"]["by_fold"][fold or windows]


def _fn(comp: str, pattern: str) -> bool:
    return comp == pattern or (_has_glob(pattern) and fnmatch.fnmatchcase(comp, pattern))


def _hit(rule: _Rule, anchor: str, comps: Tuple[str, ...]) -> Optional[str]:
    """'self' | 'inside' | 'parent' | 'name' when `rule` refuses (anchor, comps), else None."""
    if rule.mode == "name":
        return "name" if any(_fn(c, rule.parts[0]) for c in comps) else None
    if rule.root:
        return "self" if not comps else None
    if anchor != rule.anchor:
        return None
    n, m = len(rule.parts), len(comps)
    for i in range(min(n, m)):
        if not _fn(comps[i], rule.parts[i]):
            return None
    if m < n:
        return "parent"
    if m == n:
        return "self"
    return "inside" if rule.mode == "tree" else None


def _reason(rule: _Rule, rel: str) -> str:
    base = "%s %s" % (rule.mode, rule.raw)
    return base + " (parent of a protected path)" if rel == "parent" else base


def is_protected(path: Any) -> Tuple[bool, str]:
    try:
        text = _as_text(path)
    except (TypeError, ValueError):
        return True, "unusable path (empty, NUL byte or not a path)"
    windows = _is_windows()
    try:
        real, forms = _forms(text, windows)
    except (OSError, ValueError, RuntimeError) as exc:
        return True, "cannot resolve path (%s)" % type(exc).__name__
    if windows and any(":" in c for _a, comps in forms for c in comps):
        return True, "NTFS alternate data stream or invalid name"
    if any(not comps for _a, comps in forms):
        return True, "volume root"
    try:
        mounted = os.path.ismount(real)
    except (OSError, ValueError):
        mounted = True
    if mounted:
        return True, "volume root (mount point)"
    fold = windows or _case_insensitive(real)
    rules = _rules_for(fold)  # CorecleanerError propagates: no list means no verdict, never "allowed"
    for anchor, comps in forms:
        if fold:
            anchor, comps = _fold(anchor), tuple(_fold(c) for c in comps)
        for rule in rules:
            rel = _hit(rule, anchor, comps)
            if rel:
                return True, _reason(rule, rel)
    return False, ""


# ----------------------------------------------------------------------------- protected names inside a tree

# Never descended: regenerable trees full of fixtures (test certificates) that would drown the signal.
_SCAN_SKIP_DIRS = frozenset(("node_modules", "site-packages", "__pycache__"))
_ENV_TEMPLATE = re.compile(r"^\.env\.(?:example|sample|template|dist|defaults?|schema)$", re.IGNORECASE)
FIND_CAP = 100_000
FIND_MAX_HITS = 20


def _content_name_rules(fold: bool) -> List[_Rule]:
    # `.git` is a repo's own business (archive.py); every other `name` rule is a secret or user data.
    return [r for r in _rules_for(fold) if r.mode == "name" and r.parts[0] != _fold(".git") and r.parts[0] != ".git"]


def protected_component(name: str, fold: Optional[bool] = None) -> Optional[str]:
    """The `name` rule (as written in never-touch.txt) that one file name trips, else None.

    Unlike is_protected this looks at a single component and skips `.git` and the `.env.example` family.
    """
    if _ENV_TEMPLATE.match(name):
        return None
    use_fold = _is_windows() if fold is None else fold
    comp = unicodedata.normalize("NFC", name)
    if use_fold:
        comp = _fold(comp)
    for rule in _content_name_rules(use_fold):
        if _fn(comp, rule.parts[0]):
            return rule.raw
    return None


def find_protected_inside(path: Any, cap: int = FIND_CAP, skip_repos: bool = True) -> Tuple[List[str], bool]:
    """(relative paths whose NAME is protected, truncated) found INSIDE `path`, by lstat only.

    `is_protected` judges the candidate's own path; a scratch folder holding `.ssh/id_rsa` or a repo's
    ignored `.env` passes it. Matches are not descended into. Nested repos (a `.git` entry) are skipped
    when `skip_repos`, because archive.py handles their ignored files. Symlinks are never followed and
    the walk stays on one device. `truncated` = the entry cap was hit, so the answer may miss files.
    """
    root = os.fspath(path)
    try:
        real = os.path.realpath(root)
        root_dev = os.lstat(real).st_dev
        fold = _is_windows() or _case_insensitive(real)
        _content_name_rules(fold)  # a missing deny list raises here, never "nothing found"
    except OSError:
        return [], True
    hits: List[str] = []
    seen = 0
    stack = [(real, "")]
    while stack:
        cur, rel = stack.pop()
        try:
            it = os.scandir(cur)
        except OSError:
            return hits, True
        with it:
            for entry in it:
                seen += 1
                if seen > cap:
                    return hits, True
                name = entry.name
                sub = os.path.join(rel, name) if rel else name
                if protected_component(name, fold):
                    hits.append(sub)
                    if len(hits) >= FIND_MAX_HITS:
                        return hits, True  # more may follow: nobody may call this list complete
                    continue
                if name == ".git" or name in _SCAN_SKIP_DIRS:
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not stat_mod.S_ISDIR(st.st_mode):
                    continue
                if (getattr(st, "st_file_attributes", 0) & 0x400) or (st.st_dev and root_dev and st.st_dev != root_dev):
                    continue
                if skip_repos and os.path.lexists(os.path.join(entry.path, ".git")):
                    continue
                stack.append((entry.path, sub))
    return hits, False


# ----------------------------------------------------------------------------- names as data


def is_unsafe_char(ch: str) -> bool:
    """The one set sanitize_name replaces and plan.has_control refuses."""
    if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp"):
        return True  # controls, bidi and tag/format characters, lone surrogates, line separators
    return ord(ch) in _INVISIBLE_CP


def sanitize_name(s: Any, maxlen: int = 80) -> str:
    if isinstance(s, (bytes, os.PathLike)):
        s = os.fsdecode(s)
    s = str(s)
    if maxlen < 1:
        return ""
    out: List[str] = []
    in_run = False
    for ch in s:
        if is_unsafe_char(ch):
            if not in_run:
                out.append(_REPLACEMENT)
            in_run = True
        else:
            out.append(" " if unicodedata.category(ch) == "Zs" else ch)
            in_run = False
        if len(out) > maxlen:
            break
    text = "".join(out)
    if len(text) <= maxlen:
        return text
    keep = maxlen - len(_TRUNCATION_MARKER)
    return text[:keep] + _TRUNCATION_MARKER if keep > 0 else _TRUNCATION_MARKER[:maxlen]


def mark_as_data(s: Any, maxlen: int = 80) -> str:
    """sanitize_name as one JSON string literal: quotes and backslashes cannot break out of it."""
    return json.dumps(sanitize_name(s, maxlen), ensure_ascii=False)


# ----------------------------------------------------------------------------- cloud, placeholder


def _lstat(path: str) -> Any:
    return os.lstat(path)


def _finder_prefs(home: str) -> Optional[dict]:
    path = os.path.join(home, "Library", "Preferences", "com.apple.finder.plist")
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _has_icloud_xattr(path: str) -> bool:
    try:
        out = subprocess.run(
            ["/usr/bin/xattr", path], capture_output=True, text=True, timeout=5, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    return any(name.startswith("com.apple.icloud") for name in out.split())


def _icloud_desktop_documents(home: str) -> Set[str]:
    """macOS: which of Desktop/Documents are iCloud-synced. Finder prefs are authoritative when
    readable (the CloudDocs folders can exist with sync off); unreadable prefs fail closed."""
    prefs = _finder_prefs(home)
    active: Set[str] = set()
    for name, key in (("Desktop", "FXICloudDriveDesktop"), ("Documents", "FXICloudDriveDocuments")):
        flag = prefs.get(key) if prefs else None
        if flag is True or _has_icloud_xattr(os.path.join(home, name)):
            active.add(name)
        elif flag is None:
            clouddocs = os.path.join(home, "Library", "Mobile Documents", "com~apple~CloudDocs", name)
            if os.path.isdir(clouddocs):
                active.add(name)
    return active


def _dropbox_roots(home: str, windows: bool) -> List[str]:
    """Custom Dropbox locations from Dropbox's own info.json (read only, size capped)."""
    spots = [os.path.join(home, ".dropbox", "info.json")]
    if windows:
        for var in ("LOCALAPPDATA", "APPDATA"):
            if os.environ.get(var):
                spots.append(os.path.join(os.environ[var], "Dropbox", "info.json"))
    roots: List[str] = []
    for spot in spots:
        try:
            with open(spot, "r", encoding="utf-8") as fh:
                data = json.loads(fh.read(1 << 20))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            roots += [v["path"] for v in data.values() if isinstance(v, dict) and isinstance(v.get("path"), str)]
    return roots


def _cloud_rules() -> List[Tuple[str, _Rule]]:
    """[(label, tree rule)], folded; cached per (home, OneDrive*, kind) for the process."""
    kind, windows = _os_kind(), _is_windows()
    home = os.path.expanduser("~")
    onedrive = sorted((k.lower(), v) for k, v in os.environ.items() if k.lower().startswith("onedrive"))
    key = (home, tuple(onedrive), kind, os.environ.get("LOCALAPPDATA"), os.environ.get("APPDATA"))
    entry = _CACHE.get("cloud")
    if entry and entry[0] == key:
        return entry[1]
    homes = [home]
    try:
        real_home = os.path.realpath(home)
        if real_home != home:
            homes.append(real_home)
    except (OSError, ValueError):
        pass
    patterns: List[Tuple[str, str]] = []
    for h in homes:
        base = _lit(h.replace("\\", "/") if windows else h)
        patterns += [(label, base + "/" + rel) for label, rel in _CLOUD_HOME_REL]
    patterns += list(_CLOUD_ABS)
    patterns += [("OneDrive", _lit(v)) for _k, v in onedrive if v]
    patterns += [("Dropbox", _lit(p)) for p in _dropbox_roots(home, windows)]
    if kind == "macos":
        for h in homes:
            patterns += [
                ("iCloud Drive (Desktop & Documents)", _lit(h) + "/" + name)
                for name in sorted(_icloud_desktop_documents(h))
            ]
    rules: List[Tuple[str, _Rule]] = []
    for label, pattern in patterns:
        anchor, comps = _canon_parts(pattern, windows)
        if anchor and comps:
            rules.append((label, _Rule("tree", label, _fold(anchor), tuple(_fold(c) for c in comps))))
    _CACHE["cloud"] = (key, rules)
    return rules


def _cloud_path_hit(anchor: str, comps: Tuple[str, ...]) -> str:
    """Label of the sync root holding (anchor, comps), else ''. Pure string work, case-folded."""
    f_anchor, f_comps = _fold(anchor), tuple(_fold(c) for c in comps)
    for label, rule in _cloud_rules():
        if _hit(rule, f_anchor, f_comps) in ("self", "inside"):
            return label
    if _is_windows() and f_comps and f_comps[0] in _GDRIVE_WINDOWS_ROOTS:
        return "Google Drive"
    return ""


def _placeholder_reason(st: Any) -> str:
    flags = getattr(st, "st_flags", 0) or 0
    attrs = getattr(st, "st_file_attributes", 0) or 0
    if flags & SF_DATALESS:
        return "dataless placeholder (SF_DATALESS)"
    if attrs & FILE_ATTRIBUTE_RECALL_ON_OPEN:
        return "cloud placeholder (RECALL_ON_OPEN)"
    if attrs & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS:
        return "cloud placeholder (RECALL_ON_DATA_ACCESS)"
    if attrs & FILE_ATTRIBUTE_OFFLINE:
        return "offline file (FILE_ATTRIBUTE_OFFLINE)"
    blocks = getattr(st, "st_blocks", None)
    if (
        blocks is not None
        and stat_mod.S_ISREG(st.st_mode)
        and st.st_size >= _SPARSE_MIN_SIZE
        and not flags & UF_COMPRESSED
        and blocks * 512 * _SPARSE_RATIO <= st.st_size
    ):
        return "allocated blocks far below size (placeholder, sparse or compressed file)"
    return ""


def is_cloud_or_placeholder(path: Any) -> Tuple[bool, str]:
    try:
        text = _as_text(path)
    except (TypeError, ValueError):
        return True, "unusable path (empty, NUL byte or not a path)"
    windows = _is_windows()
    try:
        label = _cloud_path_hit(*_canon_parts(os.path.abspath(text), windows))
        if label:  # decided from the string: no stat, no realpath, nothing that could hydrate
            return True, "cloud-synced folder: " + label
        real, forms = _forms(text, windows)
        for form in forms:
            label = _cloud_path_hit(*form)
            if label:
                return True, "cloud-synced folder: " + label
    except (OSError, ValueError, RuntimeError) as exc:
        return True, "cannot resolve path (%s)" % type(exc).__name__
    for target in dict.fromkeys((text, real)):  # lstat never follows the final symlink
        try:
            st = _lstat(target)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as exc:
            return True, "cannot lstat (%s)" % errno.errorcode.get(exc.errno or 0, type(exc).__name__)
        reason = _placeholder_reason(st)
        if reason:
            return True, reason
    return False, ""
