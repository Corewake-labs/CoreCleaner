"""Copy, verification, per-repo manifest and INDEX.md for `migrate`. (M3, M5 of docs/SPEC-migrate.md)

walk(root) -> {rel: (kind, size, mtime_ns, target)}: kind f(ile) l(ink) d(ir) s(pecial: socket, fifo, device, a
  mount inside the tree). A node_modules folder an install rebuilds (regenerable_node_modules) is left out at any
  level, any other is kept; links are never followed; an unreadable folder raises (a tree not read to the end is
  never "the same").
copy_tree(src, dst): everything walk lists except specials, into a NEW folder `dst` (exclusive creates only).
  Links stay links, mode and mtime are kept; xattrs and ACLs too (macOS copyfile(3), Linux shutil.copystat).
verify(src, dst) -> (problem | None, facts): same set of paths, same kind, same size and sha256 of every regular
  file, same link targets, then `git fsck --no-dangling` and `git status --porcelain` equal on both sides.
remove_partial(path, root): deletes only a staging folder this run created under `root` (archive._remove_own_temp).
merge_index(dest_root, rel, row): replaces the row whose Repo cell is `rel`, appends otherwise; the rest of the
  file is kept byte for byte; written to a temp file and renamed.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import archive, gitguard
from .common import EXIT_ERROR, CorecleanerError

SKIP_NAMES = frozenset({"node_modules"})
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
MANIFEST_NAME = ".corecleaner-migrated.json"
INDEX_NAME = "INDEX.md"
INDEX_TITLE = "# Repos arquivados (CoreCleaner)"
INDEX_COLUMNS = ("Repo", "MB", "Origem", "Onde mais existe", "Data", "Manifesto")
INDEX_HEADER = "| " + " | ".join(INDEX_COLUMNS) + " |"
INDEX_RULE = "|" + "---|" * len(INDEX_COLUMNS)
_CHUNK = 1 << 20

# copyfile(3) flags, <copyfile.h>
_COPYFILE_ACL, _COPYFILE_STAT, _COPYFILE_XATTR, _COPYFILE_DATA = 1 << 0, 1 << 1, 1 << 2, 1 << 3
_COPYFILE_METADATA = _COPYFILE_ACL | _COPYFILE_STAT | _COPYFILE_XATTR
_COPYFILE_EXCL = 1 << 17
_COPYFILE_NOFOLLOW = (1 << 18) | (1 << 19)
_copyfile_fn: List[Any] = []

Entry = Tuple[str, int, int, Optional[str]]


def _mac_copyfile() -> Any:
    if sys.platform != "darwin":
        return None
    if not _copyfile_fn:
        try:
            lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            fn = lib.copyfile
            fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32]
            fn.restype = ctypes.c_int
        except (OSError, AttributeError):
            fn = None
        _copyfile_fn.append(fn)
    return _copyfile_fn[0]


def _copyfile(src: str, dst: str, flags: int) -> None:
    fn = _mac_copyfile()
    if fn(os.fsencode(src), os.fsencode(dst), None, flags | _COPYFILE_NOFOLLOW) != 0:
        err = ctypes.get_errno() or errno.EIO
        raise OSError(err, os.strerror(err), src)


def _rel_key(rel: str) -> List[str]:
    return rel.split(os.sep)


# ---------------------------------------------------------------- walk

def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _is_file(path: str) -> bool:
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def regenerable_node_modules(root: str, nm: str) -> bool:
    """True only when an install rebuilds `nm`: package.json beside it, a lockfile there or in a folder above it
    inside `root`, every entry readable and no link in it that leaves `root` (npm link, a hand-made link).
    Anything else (hand-patched files with no manifest, say) is project content and is copied."""
    parent = os.path.dirname(nm)
    if not _within(parent, root) or not _is_file(os.path.join(parent, "package.json")):
        return False
    cur = parent
    while not any(_is_file(os.path.join(cur, n)) for n in LOCKFILES):
        if cur == root or not _within(cur, root):
            return False
        cur = os.path.dirname(cur)
    errors: List[OSError] = []
    for dirpath, dirs, files in os.walk(nm, onerror=errors.append):
        for name in dirs + files:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                try:
                    target = os.readlink(full)
                except OSError:
                    return False
                if not _within(os.path.normpath(os.path.join(dirpath, target)), root):
                    return False
    return not errors


def walk(root: str, skip_top: Tuple[str, ...] = ()) -> Dict[str, Entry]:
    top = os.lstat(root)
    out: Dict[str, Entry] = {}
    stack = [""]
    while stack:
        rel_dir = stack.pop()
        with os.scandir(os.path.join(root, rel_dir) if rel_dir else root) as it:
            for e in it:
                if not rel_dir and e.name in skip_top:
                    continue
                if e.name in SKIP_NAMES and e.is_dir(follow_symlinks=False) and regenerable_node_modules(root, e.path):
                    continue
                rel = os.path.join(rel_dir, e.name) if rel_dir else e.name
                st = e.stat(follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode):
                    out[rel] = ("l", 0, st.st_mtime_ns, os.readlink(e.path))
                elif stat.S_ISDIR(st.st_mode) and st.st_dev == top.st_dev:
                    out[rel] = ("d", 0, st.st_mtime_ns, None)
                    stack.append(rel)
                elif stat.S_ISREG(st.st_mode):
                    out[rel] = ("f", st.st_size, st.st_mtime_ns, None)
                else:
                    out[rel] = ("s", 0, st.st_mtime_ns, None)
    return out


def fingerprint(root: str) -> Dict[str, Tuple[str, int, int]]:
    """List, size and mtime of what is copied: what must not move between the copy and the Trash."""
    return {rel: e[:3] for rel, e in walk(root).items()}


# ---------------------------------------------------------------- copy

def _times(src_st: os.stat_result, dst: str) -> None:
    os.utime(dst, ns=(src_st.st_atime_ns, src_st.st_mtime_ns), follow_symlinks=False)


def _copy_file(src: str, dst: str) -> None:
    st = os.lstat(src)
    if _mac_copyfile() is not None:
        _copyfile(src, dst, _COPYFILE_METADATA | _COPYFILE_DATA | _COPYFILE_EXCL)
    else:
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with open(src, "rb") as fin, os.fdopen(fd, "wb") as fout:
            shutil.copyfileobj(fin, fout, _CHUNK)
            fout.flush()
            os.fsync(fout.fileno())
        shutil.copystat(src, dst, follow_symlinks=False)  # mode, times, flags, Linux xattrs
    _times(st, dst)


def _dir_meta(src: str, dst: str) -> None:
    st = os.lstat(src)
    if _mac_copyfile() is not None:
        _copyfile(src, dst, _COPYFILE_METADATA)
    else:
        shutil.copystat(src, dst, follow_symlinks=False)
    _times(st, dst)


def _link(src: str, dst: str, target: str) -> None:
    os.symlink(target, dst)
    try:
        _times(os.lstat(src), dst)
    except (NotImplementedError, OSError):
        pass  # a link's own mtime cannot be set everywhere; its target text is what is verified


def copy_tree(src: str, dst: str) -> Dict[str, Any]:
    """Copy into `dst`, which must not exist (created here, 0700 until its own mode is applied last)."""
    entries = walk(src)
    os.mkdir(dst, 0o700)
    dirs: List[str] = []
    files = total = 0
    specials: List[str] = []
    for rel in sorted(entries, key=_rel_key):
        kind, size, _mt, target = entries[rel]
        s, d = os.path.join(src, rel), os.path.join(dst, rel)
        if kind == "d":
            os.mkdir(d, 0o700)
            dirs.append(rel)
        elif kind == "l":
            _link(s, d, target or "")
        elif kind == "f":
            _copy_file(s, d)
            files += 1
            total += size
        else:
            specials.append(rel)
    for rel in sorted(dirs, key=_rel_key, reverse=True):  # children first: writing into a dir moves its mtime
        _dir_meta(os.path.join(src, rel), os.path.join(dst, rel))
    _dir_meta(src, dst)
    return {"files": files, "bytes": total, "specials": specials}


def remove_partial(path: str, root: str) -> None:
    """Delete the staging copy THIS run created (never anything else: archive refuses outside `root`)."""
    if not os.path.lexists(path):
        return
    for cur, dirs, _files in os.walk(path):
        for name in dirs:
            full = os.path.join(cur, name)
            if not os.path.islink(full):
                os.chmod(full, stat.S_IRWXU)
    if not os.path.islink(path):
        os.chmod(path, stat.S_IRWXU)
    archive._remove_own_temp(Path(path), Path(root))


# ---------------------------------------------------------------- verification

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _line(rel: str, kind: str, size: int, digest: str) -> str:
    return "%s\t%s\t%d\t%s" % (kind, os.fsencode(rel).decode("utf-8", "backslashreplace"), size, digest)


def _run_git(repo: str) -> Any:
    def run(*args: str) -> Tuple[int, str]:
        try:
            proc = archive._git(repo, *args, check=False)
        except CorecleanerError:
            return 127, ""
        return proc.returncode, proc.stdout.decode("utf-8", "replace")
    return run


def _git_same(src: str, dst: str) -> Optional[str]:
    # The copy sits elsewhere: an includeIf "gitdir:<disk>/" can match there and nowhere else.
    unsafe = gitguard.unsafe_config(_run_git(dst), dst)
    if unsafe:
        return "the copy's git config runs programs where it now lives (%s): refused" % ", ".join(unsafe)
    ours = b"?? " + MANIFEST_NAME.encode("ascii")
    # --no-optional-locks: status must not rewrite .git/index, or a resumed copy never matches the original again.
    for label, args in (("git fsck", ("fsck", "--no-dangling", "--no-progress")),
                        ("git status", ("--no-optional-locks", "status", "--porcelain=v1", "-z", "--untracked-files=normal",
                                        "--ignore-submodules=none"))):
        try:
            a = archive._git(src, *args, check=False, timeout=archive._WRITE_TIMEOUT)
            b = archive._git(dst, *args, check=False, timeout=archive._WRITE_TIMEOUT)
        except CorecleanerError:
            return label + " could not run"
        out_b = b"\0".join(e for e in b.stdout.split(b"\0") if e != ours)
        if (a.returncode, a.stdout) != (b.returncode, out_b):
            return label + " differs between the copy and the original"
    return None


def verify(src: str, dst: str) -> Tuple[Optional[str], Dict[str, Any]]:
    """(first difference or None, {files, bytes, merkle, specials}). Reads both trees from disk again."""
    try:
        a, b = walk(src), walk(dst, skip_top=(MANIFEST_NAME,))
    except OSError as exc:
        return "could not read a tree to verify it (%s)" % (exc.strerror or type(exc).__name__), {}
    specials = sorted(r for r, e in a.items() if e[0] == "s")
    want = {r: e for r, e in a.items() if e[0] != "s"}
    if set(want) != set(b):
        return "the copy does not hold the same set of paths", {}
    lines: List[str] = []
    files = total = 0
    for rel in sorted(want, key=_rel_key):
        (ka, sa, _ma, ta), (kb, sb, _mb, tb) = want[rel], b[rel]
        if ka != kb:
            return "an entry has another type in the copy", {}
        if ka == "l":
            if ta != tb:
                return "a symlink points elsewhere in the copy", {}
            lines.append(_line(rel, "l", 0, os.fsencode(ta or "").hex()))
        elif ka == "f":
            if sa != sb:
                return "a file has another size in the copy", {}
            try:
                da, db = sha256_file(os.path.join(src, rel)), sha256_file(os.path.join(dst, rel))
            except OSError:
                return "a file could not be read to verify it", {}
            if da != db:
                return "a file has other content in the copy (sha256 differs)", {}
            files += 1
            total += sa
            lines.append(_line(rel, "f", sa, da))
        else:
            lines.append(_line(rel, "d", 0, ""))
    problem = _git_same(src, dst)
    if problem:
        return problem, {}
    merkle = hashlib.sha256("\n".join(lines).encode("utf-8", "surrogatepass")).hexdigest()
    return None, {"files": files, "bytes": total, "merkle": merkle, "entries": len(lines), "specials": specials}


# ---------------------------------------------------------------- manifest and INDEX.md

def write_atomic(path: str, data: bytes) -> None:
    tmp = "%s.tmp-%s" % (path, os.urandom(4).hex())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.lexists(tmp):
            os.unlink(tmp)  # our own temp file next to the target, never a user file
        raise


def write_manifest(folder: str, manifest: dict) -> str:
    path = os.path.join(folder, MANIFEST_NAME)
    write_atomic(path, (json.dumps(manifest, ensure_ascii=True, indent=1, sort_keys=True) + "\n").encode("ascii"))
    return path


def read_manifest(folder: str) -> Optional[dict]:
    path = os.path.join(folder, MANIFEST_NAME)
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _cell(value: Any) -> str:
    text = " ".join(str(value).split())
    return text.replace("\\", "\\\\").replace("|", "\\|")


def _cells(line: str) -> List[str]:
    parts: List[str] = []
    cur, esc = "", False
    for ch in line.strip():
        if esc:
            cur += ch
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == "|":
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    parts.append(cur.strip())
    return parts[1:-1] if len(parts) >= 2 else parts


def index_row(rel: str, nbytes: int, origin: str, where: str, date: str, manifest_rel: str) -> str:
    mb = max(1, int(round(nbytes / 1e6))) if nbytes else 0
    return "| " + " | ".join(_cell(v) for v in (rel.replace(os.sep, "/"), mb, origin, where, date, manifest_rel)) + " |"


def merge_index(dest_root: str, rel: str, row: str) -> str:
    path = os.path.join(dest_root, INDEX_NAME)
    key = rel.replace(os.sep, "/")
    try:
        text: Optional[str] = Path(path).read_bytes().decode("utf-8", "surrogateescape")
    except FileNotFoundError:
        text = None
    except OSError as exc:
        raise CorecleanerError(EXIT_ERROR, "cannot read INDEX.md on the destination: " + str(exc.strerror))
    if text is None:
        new = "\n".join((INDEX_TITLE, "", INDEX_HEADER, INDEX_RULE, row, ""))
    else:
        lines = text.split("\n")
        head = next((i for i, ln in enumerate(lines)
                     if [c.casefold() for c in _cells(ln)][:1] == ["repo"] and len(_cells(ln)) >= 4), None)
        if head is None:
            tail = "" if text.endswith("\n") or not text else "\n"
            new = text + tail + "\n".join(("", INDEX_HEADER, INDEX_RULE, row, ""))
        else:
            end = head + 2
            hit = None
            while end < len(lines) and lines[end].lstrip().startswith("|"):
                if hit is None and _cells(lines[end])[:1] == [key]:
                    hit = end
                end += 1
            if hit is not None:
                lines[hit] = row
            else:
                lines.insert(end, row)
            new = "\n".join(lines)
    write_atomic(path, new.encode("utf-8", "surrogateescape"))
    return path
