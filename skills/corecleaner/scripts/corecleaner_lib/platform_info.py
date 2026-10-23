"""Platform facts: OS, arch, Trash availability, free space. (T1; subcommands `check`, `free`)

Read-only, except that is_case_insensitive may, as a last resort, create and delete one temp file
inside the tool's own state dir. The only module whose subcommands may run as root/admin. Named
platform_info so it never shadows the stdlib `platform`.

run(args) dispatches on args.cmd: "check" -> check(); "free" -> free(args.path).

check() -> dict
  os              "macos" | "linux" | "windows"  (any other sys.platform is returned raw, with a warning)
  os_version      str
  arch            "arm64" | "x86_64" | raw machine string (Python under Rosetta reports the native arm64)
  arch_supported  bool   True only for targets pinned in references/pins.tsv (built-in table while
                         that file does not exist); False -> bootstrap exits 10
  python          "3.x.y"
  is_admin        bool
  trash           {"available": bool, "tool": str | None, "reason": str}   (HOME volume)
  dua             {"found": bool, "path": str | None, "version": str | None, "managed": bool}
  git, rg         {"found": bool, "version": str | None}
                  found means "runs and reports a version" (the Apple git shim without Command Line
                  Tools counts as not found: running it would open an installer dialog)
  volumes         [{"mount", "fs", "total_bytes", "free_bytes", "case_insensitive", "trash",
                    "trash_detail"}]  writable user-visible volumes only (read-only, pseudo and
                    macOS nobrowse volumes are left out, except the one holding HOME)
  warnings        [str]   (the Windows beta note is added by corecleaner.py, not here)

free(path=None) -> dict   (path defaults to HOME)
  {"path": str, "total_bytes": int, "used_bytes": int, "free_bytes": int, "ts": now_iso()}
  Metric of record for any gain claim: free_after - free_before from shutil.disk_usage.

os_kind() -> "macos" | "linux" | "windows"
dua_target(os_name=None, arch=None) -> str | None     Rust target triple of the dua build, for pins.tsv
is_case_insensitive(path) -> bool
  Tests the real filesystem, in this order: (1) look up the case-swapped spelling of an existing
  path component that lives in the same volume (pure stat); (2) macOS pathconf(_PC_CASE_SENSITIVE);
  (3) same lookup on an entry of the nearest directory; (4) a temp file in the state dir, when it is
  on the same volume. Cannot tell -> True (fail closed: the deny list then compares case-folded,
  which can only protect more).
trash_available(path) -> (bool, str)
  (available, tool-or-reason) for the volume holding `path`. False on volumes without a Trash
  (network, read-only, no .Trashes / .Trash-uid, Windows non-fixed drive or NukeOnDelete) and
  whenever the answer is unknown. Callers exit 30 when False. Tool names: "/usr/bin/trash",
  "osascript", "gio", "trash-put", "recycle-bin".
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import common
from .common import CorecleanerError

# Aliases so tests can simulate a filesystem without touching os globally.
_lstat = os.lstat
_scandir = os.scandir

_PROBE_TIMEOUT = 5
_KNOWN_OS = ("macos", "linux", "windows")
_ARCH_ALIASES = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x86_64", "amd64": "x86_64", "x64": "x86_64"}
_DUA_TARGETS = {
    ("macos", "arm64"): "aarch64-apple-darwin",
    ("macos", "x86_64"): "x86_64-apple-darwin",
    ("linux", "x86_64"): "x86_64-unknown-linux-musl",
    ("linux", "arm64"): "aarch64-unknown-linux-musl",
    ("windows", "x86_64"): "x86_64-pc-windows-msvc",
    ("windows", "arm64"): "aarch64-pc-windows-msvc",
}
_PINS = Path(__file__).resolve().parents[2] / "references" / "pins.tsv"

_NETWORK_FS = frozenset(
    {"nfs", "nfs4", "smbfs", "cifs", "smb3", "afpfs", "webdav", "ftp", "afs", "ncpfs", "9p", "ceph", "glusterfs", "lustre"}
)
_NETWORK_FUSE = ("fuse.sshfs", "fuse.rclone", "fuse.s3fs", "fuse.gcsfuse", "fuse.davfs", "fuse.curlftpfs")
_PSEUDO_FS = frozenset(
    {
        "devfs", "autofs", "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "ramfs", "cgroup", "cgroup2",
        "securityfs", "debugfs", "tracefs", "configfs", "fusectl", "pstore", "bpf", "mqueue", "hugetlbfs",
        "binfmt_misc", "rpc_pipefs", "nsfs", "efivarfs", "overlay", "squashfs", "selinuxfs", "nfsd",
        "fuse.gvfsd-fuse", "fuse.portal", "fuse.snapfuse",
    }
)

_MAC_PC_CASE_SENSITIVE = 11  # <sys/unistd.h>; os.pathconf takes the bare integer
_MAC_TRASH = "/usr/bin/trash"  # fixed path on purpose: a PATH `trash` may be another tool
_MAC_OSASCRIPT = "/usr/bin/osascript"

_DRIVE_FIXED = 3
_BITBUCKET_VOLUME = r"Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume"
_EXPLORER_POLICY = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

_ASCII_SWAP = str.maketrans(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_MAC_MOUNT_RE = re.compile(r"^(?P<dev>.+?) on (?P<mnt>/.*?) \((?P<opts>[^()]*)\)$")
_DF_RE = re.compile(r"^.+?\s+\d+\s+\d+\s+\d+\s+(?:\d+%|-)\s+(?P<mnt>/.*)$")
_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")


# --------------------------------------------------------------------------- basics


def os_kind() -> str:
    plat = sys.platform
    if plat == "darwin":
        return "macos"
    if plat == "win32":
        return "windows"
    if plat.startswith("linux"):
        return "linux"
    return plat


def _run(argv: List[str]) -> Optional[str]:
    """stdout+stderr of a short read-only command; None if it cannot run or exits non-zero."""
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=_PROBE_TIMEOUT,
            env=dict(os.environ, LC_ALL="C"),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "replace")


def _version_of(exe: str) -> Optional[str]:
    out = _run([exe, "--version"])
    lines = out.strip().splitlines() if out else []
    match = _VERSION_RE.search(lines[0]) if lines else None
    return match.group(0) if match else None


def _tool(name: str) -> dict:
    path = shutil.which(name)
    if path is None:
        return {"found": False, "version": None}
    if os_kind() == "macos" and path == "/usr/bin/" + name and _run(["/usr/bin/xcode-select", "-p"]) is None:
        # Apple shim without Command Line Tools: executing it opens an installer dialog.
        return {"found": False, "version": None}
    version = _version_of(path)
    return {"found": version is not None, "version": version}


def _state_dir_path() -> str:
    """Where common.state_dir() points, without creating it (check must not write).

    Mirror of common.state_dir(); tests assert both agree.
    """
    override = os.environ.get(common.STATE_ENV)
    if override:
        return str(Path(override).expanduser())
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return str(Path(base) / "corecleaner")
    return str(Path.home() / ".corecleaner")


def _managed_dua_path(kind: str) -> str:
    """Where `bootstrap` installs dua (bootstrap.install_dir), computed without creating anything."""
    if kind == "windows":
        return os.path.join(_state_dir_path(), "bin", "dua.exe")
    return os.path.join(str(Path.home()), ".local", "bin", "dua")


def _find_dua(kind: str) -> dict:
    managed = _managed_dua_path(kind)
    candidates = [(managed, True)]
    on_path = shutil.which("dua")
    if on_path:
        candidates.append((on_path, False))
    for path, is_managed in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            version = _version_of(path)
            return {"found": version is not None, "path": path, "version": version, "managed": is_managed}
    return {"found": False, "path": None, "version": None, "managed": False}


def _arch() -> Tuple[str, List[str]]:
    machine = platform.machine().lower()
    arch = _ARCH_ALIASES.get(machine, machine)
    warnings: List[str] = []
    if os_kind() == "macos" and arch == "x86_64":
        out = _run(["/usr/sbin/sysctl", "-n", "hw.optional.arm64"])
        if out and out.strip() == "1":
            warnings.append("Python runs under Rosetta on an Apple Silicon Mac; reporting the native arch arm64")
            arch = "arm64"
    return arch, warnings


def _os_version(kind: str) -> str:
    if kind == "macos":
        return platform.mac_ver()[0] or platform.release()
    if kind == "linux":
        try:
            with open("/etc/os-release", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip("\"'")
        except OSError:
            pass
    return platform.version() or platform.release()


def dua_target(os_name: Optional[str] = None, arch: Optional[str] = None) -> Optional[str]:
    return _DUA_TARGETS.get((os_name or os_kind(), arch or _arch()[0]))


def _pinned_targets() -> Optional[set]:
    """Every tab-separated field of pins.tsv (comments skipped); None while the file does not exist."""
    try:
        text = _PINS.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    fields = set()
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            fields.update(part.strip() for part in line.split("\t"))
    return fields


def _arch_supported(kind: str, arch: str) -> bool:
    target = dua_target(kind, arch)
    if target is None:
        return False
    pinned = _pinned_targets()
    return True if pinned is None else target in pinned


# --------------------------------------------------------------------------- volumes


def _existing_ancestor(path: str) -> Optional[str]:
    """realpath of `path`, or of its nearest existing parent; None if nothing exists."""
    real = os.path.realpath(os.path.expanduser(path))
    while not os.path.exists(real):
        parent = os.path.dirname(real)
        if parent == real:
            return None
        real = parent
    return real


def _unescape_mount(text: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), text)


def _parse_mac_mounts(text: str) -> List[dict]:
    rows = []
    for line in text.splitlines():
        m = _MAC_MOUNT_RE.match(line)
        if m:
            parts = [p.strip() for p in m.group("opts").split(",") if p.strip()]
            rows.append({"device": m.group("dev"), "mount": m.group("mnt"), "fs": parts[0] if parts else None, "opts": set(parts[1:])})
    return rows


def _parse_linux_mounts(text: str) -> List[dict]:
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            rows.append(
                {"device": _unescape_mount(parts[0]), "mount": _unescape_mount(parts[1]), "fs": parts[2], "opts": set(parts[3].split(","))}
            )
    return rows


def _mounts() -> List[dict]:
    """[{"device", "mount", "fs", "opts": set}] from `mount` (macOS) or /proc/self/mounts (Linux)."""
    kind = os_kind()
    if kind == "macos":
        return _parse_mac_mounts(_run(["/sbin/mount"]) or "")
    if kind == "linux":
        try:
            with open("/proc/self/mounts", encoding="utf-8", errors="replace") as fh:
                return _parse_linux_mounts(fh.read())
        except OSError:
            return []
    return []


def _df_mount(path: str) -> Optional[str]:
    """Mount point of the volume holding `path`, as the OS itself reports it (handles APFS firmlinks)."""
    df = shutil.which("df")
    out = _run([df, "-Pk", path]) if df else None
    for line in reversed((out or "").strip().splitlines()):
        m = _DF_RE.match(line)
        if m:
            return m.group("mnt")
    return None


def _is_under(path: str, root: str) -> bool:
    return root == "/" or path == root or path.startswith(root.rstrip("/") + "/")


def _volume(path: str) -> Optional[dict]:
    """{"mount", "fs", "opts"} of the volume holding `path` (POSIX); None when it cannot be identified."""
    anchor = _existing_ancestor(path)
    if anchor is None:
        return None
    mounts = _mounts()
    mount = _df_mount(anchor)
    entry = None
    if mount is not None:
        for row in mounts:
            if row["mount"] == mount:
                entry = row  # the last of stacked mounts wins
    else:
        for row in mounts:
            if _is_under(anchor, row["mount"]) and (entry is None or len(row["mount"]) >= len(entry["mount"])):
                entry = row
        mount = entry["mount"] if entry else None
    if mount is None:
        return None
    return {"mount": mount, "fs": entry["fs"] if entry else None, "opts": entry["opts"] if entry else set()}


def _is_network(kind: str, fs: Optional[str], opts: set) -> bool:
    if fs is None:
        return False
    if fs in _NETWORK_FS or fs.startswith(_NETWORK_FUSE):
        return True
    return kind == "macos" and "local" not in opts  # macOS marks every local mount "local"


def _is_read_only(kind: str, opts: set) -> bool:
    return ("read-only" if kind == "macos" else "ro") in opts


def _blocker(kind: str, vol: dict) -> Optional[str]:
    if _is_network(kind, vol["fs"], vol["opts"]):
        return "network volume (%s) has no Trash" % vol["fs"]
    if _is_read_only(kind, vol["opts"]):
        return "volume %s is read-only" % vol["mount"]
    return None


# --------------------------------------------------------------------------- case sensitivity


def _case_pair(parent: str, name: str) -> Optional[bool]:
    """Are `parent/name` and its ASCII case-swapped spelling the same entry?

    True = same entry (insensitive), False = swapped spelling absent or another entry (sensitive),
    None = nothing to compare (no ASCII letters) or a lookup error.
    """
    swapped = name.translate(_ASCII_SWAP)
    if swapped == name:
        return None
    try:
        first = _lstat(os.path.join(parent, name))
    except OSError:
        return None
    try:
        second = _lstat(os.path.join(parent, swapped))
    except FileNotFoundError:
        return False
    except OSError:
        return None
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _components_probe(real: str, dev: int) -> Optional[bool]:
    cur = real
    while True:
        parent, name = os.path.split(cur)
        if not name or parent == cur:
            return None
        try:
            parent_dev = _lstat(parent).st_dev
        except OSError:
            return None
        # Only a lookup done inside the target's own volume says anything about it (a mount point
        # name is resolved by the parent volume).
        if parent_dev == dev:
            found = _case_pair(parent, name)
            if found is not None:
                return found
        cur = parent


def _metadata_probe(real: str) -> Optional[bool]:
    if sys.platform != "darwin":
        return None
    try:
        value = os.pathconf(real, _MAC_PC_CASE_SENSITIVE)
    except (OSError, ValueError):
        return None
    return value == 0 if value in (0, 1) else None


def _entries_probe(directory: str, dev: int, limit: int = 256) -> Optional[bool]:
    try:
        with _scandir(directory) as entries:
            for index, entry in enumerate(entries):
                if index >= limit:
                    break
                try:
                    if entry.stat(follow_symlinks=False).st_dev != dev:
                        continue
                except OSError:
                    continue
                found = _case_pair(directory, entry.name)
                if found is not None:
                    return found
    except OSError:
        return None
    return None


def _state_dir_probe(dev: int) -> Optional[bool]:
    try:
        directory = str(common.state_dir())
        if _lstat(directory).st_dev != dev:
            return None
        fd, tmp = tempfile.mkstemp(prefix=".CaseProbe-", dir=directory)
    except (OSError, CorecleanerError):
        return None
    os.close(fd)
    try:
        return _case_pair(directory, os.path.basename(tmp))
    finally:
        try:
            os.unlink(tmp)  # our own temp file inside our own state dir, never a user path
        except OSError:
            pass


def is_case_insensitive(path: str) -> bool:
    real = _existing_ancestor(path)
    if real is not None:
        try:
            dev = _lstat(real).st_dev
        except OSError:
            dev = None
        if dev is not None:
            found = _components_probe(real, dev)
            if found is None:
                found = _metadata_probe(real)
            if found is None and os.path.isdir(real):
                found = _entries_probe(real, dev)
            if found is None:
                found = _state_dir_probe(dev)
            if found is not None:
                return found
    return True


# --------------------------------------------------------------------------- Trash


def _home_mount() -> Optional[str]:
    anchor = _existing_ancestor("~")
    return _df_mount(anchor) if anchor else None


def _trash_macos(vol: dict) -> Tuple[bool, str]:
    if os.path.isfile(_MAC_TRASH) and os.access(_MAC_TRASH, os.X_OK):
        tool = _MAC_TRASH
    elif os.path.isfile(_MAC_OSASCRIPT) and os.access(_MAC_OSASCRIPT, os.X_OK):
        tool = "osascript"
    else:
        return False, "no Trash tool: %s and osascript are missing" % _MAC_TRASH
    blocked = _blocker("macos", vol)
    if blocked:
        return False, blocked
    if vol["mount"] == _home_mount():
        return True, tool  # ~/.Trash
    trashes = os.path.join(vol["mount"], ".Trashes")
    if os.path.isdir(trashes) and not os.path.islink(trashes):
        return True, tool
    return False, "volume %s has no .Trashes folder (trash one file there with Finder first)" % vol["mount"]


def _linux_topdir_trash(topdir: str, uid: int) -> Tuple[bool, str]:
    """XDG Trash spec, section 'Trash directories' for a volume other than the home one."""
    shared = os.path.join(topdir, ".Trash")
    try:
        info = _lstat(shared)  # lstat: a symlink is not a directory here, as the spec demands
    except OSError:
        info = None
    if info is not None and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX:
        user = os.path.join(shared, str(uid))
        if os.path.isdir(user) and os.access(user, os.W_OK | os.X_OK):
            return True, ".Trash/%d" % uid
        if os.access(shared, os.W_OK | os.X_OK):
            return True, ".Trash/%d can be created" % uid
    own = os.path.join(topdir, ".Trash-%d" % uid)
    if os.path.isdir(own) and not os.path.islink(own) and os.access(own, os.W_OK | os.X_OK):
        return True, ".Trash-%d" % uid
    if os.access(topdir, os.W_OK | os.X_OK):
        return True, ".Trash-%d can be created" % uid
    return False, "no usable Trash directory on volume %s (.Trash/%d or .Trash-%d)" % (topdir, uid, uid)


def _trash_linux(vol: dict) -> Tuple[bool, str]:
    tool = "gio" if shutil.which("gio") else ("trash-put" if shutil.which("trash-put") else None)
    if tool is None:
        return False, "no Trash tool: install gio (glib) or trash-cli (trash-put)"
    blocked = _blocker("linux", vol)
    if blocked:
        return False, blocked
    data_home = os.environ.get("XDG_DATA_HOME", "")
    if not os.path.isabs(data_home):
        data_home = os.path.join(os.path.expanduser("~"), ".local", "share")
    anchor = _existing_ancestor(data_home)
    if anchor and _df_mount(anchor) == vol["mount"]:
        if os.access(anchor, os.W_OK | os.X_OK):
            return True, tool  # home Trash: $XDG_DATA_HOME/Trash
        return False, "cannot write to %s, so the home Trash cannot be created" % anchor
    ok, detail = _linux_topdir_trash(vol["mount"], os.getuid())
    return (True, tool) if ok else (False, detail)


def _win_drive_root(path: str) -> Optional[str]:
    real = os.path.realpath(os.path.abspath(path))
    if real.startswith("\\\\?\\UNC\\"):
        return None
    if real.startswith("\\\\?\\"):
        real = real[4:]
    drive = os.path.splitdrive(real)[0]
    return drive + "\\" if len(drive) == 2 and drive[1] == ":" else None


def _win_drive_type(root: str) -> int:
    import ctypes

    return int(ctypes.windll.kernel32.GetDriveTypeW(root))  # type: ignore[attr-defined]


def _win_volume_guid(root: str) -> Optional[str]:
    import ctypes

    buf = ctypes.create_unicode_buffer(64)
    if not ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(root, buf, 64):  # type: ignore[attr-defined]
        return None
    match = re.search(r"\{[0-9A-Fa-f-]{36}\}", buf.value)
    return match.group(0).lower() if match else None


def _win_fs_name(root: str) -> Optional[str]:
    import ctypes

    buf = ctypes.create_unicode_buffer(32)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(root, None, 0, None, None, None, buf, 32)  # type: ignore[attr-defined]
    return buf.value if ok else None


def _win_drives() -> List[str]:
    import ctypes

    mask = ctypes.windll.kernel32.GetLogicalDrives()  # type: ignore[attr-defined]
    return ["%s:\\" % chr(65 + i) for i in range(26) if mask & (1 << i)]


def _reg_open(hive: str, subkey: str):
    import winreg

    root = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[hive]
    return winreg.OpenKey(root, subkey)


def _reg_subkeys(hive: str, subkey: str) -> List[str]:
    import winreg

    try:
        key = _reg_open(hive, subkey)
    except FileNotFoundError:
        return []
    names: List[str] = []
    with key:
        while True:
            try:
                names.append(winreg.EnumKey(key, len(names)))
            except OSError:  # ERROR_NO_MORE_ITEMS
                return names


def _reg_dword(hive: str, subkey: str, name: str) -> Optional[int]:
    import winreg

    try:
        key = _reg_open(hive, subkey)
    except FileNotFoundError:
        return None
    with key:
        try:
            value, _kind = winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            return None
    return value if isinstance(value, int) else None


def _trash_windows(path: str) -> Tuple[bool, str]:
    if not (shutil.which("powershell") or shutil.which("pwsh")):
        return False, "no PowerShell, so the Recycle Bin cannot be driven"
    root = _win_drive_root(path)
    if root is None:
        return False, "path is not on a local drive letter (network share?); no Recycle Bin"
    drive = root[:2]
    drive_type = _win_drive_type(root)
    if drive_type != _DRIVE_FIXED:
        return False, "drive %s is not a fixed local disk (type %d); deletes there skip the Recycle Bin" % (drive, drive_type)
    guid = _win_volume_guid(root)
    if guid is None:
        return False, "cannot identify the volume of %s" % drive
    for hive in ("HKCU", "HKLM"):
        if _reg_dword(hive, _EXPLORER_POLICY, "NoRecycleFiles"):
            return False, "policy NoRecycleFiles turns the Recycle Bin off"
    for name in _reg_subkeys("HKCU", _BITBUCKET_VOLUME):
        if name.strip("{}").lower() == guid.strip("{}"):
            if _reg_dword("HKCU", _BITBUCKET_VOLUME + "\\" + name, "NukeOnDelete"):
                return False, "drive %s is set to delete files immediately (NukeOnDelete)" % drive
    return True, "recycle-bin"


def _trash_for(kind: str, path: str, vol: Optional[dict]) -> Tuple[bool, str]:
    if kind == "windows":
        return _trash_windows(path)
    if kind not in ("macos", "linux"):
        return False, "unsupported OS: " + kind
    vol = vol or _volume(path)
    if vol is None:
        return False, "cannot identify the volume of the path"
    return _trash_macos(vol) if kind == "macos" else _trash_linux(vol)


def trash_available(path: str) -> Tuple[bool, str]:
    try:
        return _trash_for(os_kind(), path, None)
    except OSError as exc:  # unknown means no: callers refuse to trash
        return False, "cannot determine Trash availability: " + (exc.strerror or type(exc).__name__)


# --------------------------------------------------------------------------- check / free


def _volume_row(mount: str, fs: Optional[str], trash: Tuple[bool, str]) -> Optional[dict]:
    try:
        total, _used, free_bytes = shutil.disk_usage(mount)
    except OSError:
        return None
    return {
        "mount": mount,
        "fs": fs,
        "total_bytes": total,
        "free_bytes": free_bytes,
        "case_insensitive": is_case_insensitive(mount),
        "trash": trash[0],
        "trash_detail": trash[1],
    }


def _posix_volumes(kind: str) -> List[dict]:
    home_mount = _home_mount()
    seen: Dict[str, dict] = {}
    for row in _mounts():
        mount, fs, opts = row["mount"], row["fs"], row["opts"]
        if fs is None or mount in seen:
            continue
        if mount != home_mount:
            if fs in _PSEUDO_FS or _is_read_only(kind, opts) or (kind == "macos" and "nobrowse" in opts):
                continue
        seen[mount] = {"mount": mount, "fs": fs, "opts": opts}
    if home_mount and home_mount not in seen:  # e.g. an overlay root inside a container
        home_vol = _volume("~")
        if home_vol:
            seen[home_mount] = home_vol
    volumes = []
    for vol in seen.values():
        try:
            trash = _trash_for(kind, vol["mount"], vol)
        except OSError as exc:
            trash = (False, "cannot determine Trash availability: " + (exc.strerror or type(exc).__name__))
        built = _volume_row(vol["mount"], vol["fs"], trash)
        if built:
            volumes.append(built)
    return volumes


def _windows_volumes() -> List[dict]:
    volumes = []
    for root in _win_drives():
        if _win_drive_type(root) not in (2, 3, 4, 6):  # removable, fixed, network, RAM disk
            continue
        try:
            trash = _trash_windows(root)
        except OSError as exc:
            trash = (False, "cannot determine Trash availability: " + (exc.strerror or type(exc).__name__))
        built = _volume_row(root, _win_fs_name(root), trash)
        if built:
            volumes.append(built)
    return volumes


def check() -> dict:
    kind = os_kind()
    arch, warnings = _arch()
    supported = _arch_supported(kind, arch)
    if kind not in _KNOWN_OS:
        warnings.append("unsupported OS %r: nothing will be trashed" % kind)
    elif not supported:
        warnings.append("no pinned dua build for %s/%s: bootstrap exits 10; scan runs in basic mode" % (kind, arch))
    dua = _find_dua(kind)
    if dua["path"] and not dua["found"]:
        warnings.append("dua at %s did not report a version; treated as not installed" % dua["path"])
    ok, detail = trash_available(os.path.expanduser("~"))
    if kind == "windows":
        volumes = _windows_volumes()
    elif kind in ("macos", "linux"):
        volumes = _posix_volumes(kind)
    else:
        volumes = []
    return {
        "os": kind,
        "os_version": _os_version(kind),
        "arch": arch,
        "arch_supported": supported,
        "python": platform.python_version(),
        "is_admin": common.is_admin(),
        "trash": {"available": ok, "tool": detail if ok else None, "reason": "ok" if ok else detail},
        "dua": dua,
        "git": _tool("git"),
        "rg": _tool("rg"),
        "volumes": volumes,
        "settings": common.read_settings(),
        "onboarding": not common.settings_path().exists(),  # first run on this machine: ask about dua and language
        "warnings": warnings,
    }


def free(path: Optional[str] = None) -> dict:
    target = os.path.abspath(os.path.expanduser(path or "~"))
    try:
        total, used, free_bytes = shutil.disk_usage(target)
    except OSError as exc:
        raise CorecleanerError(common.EXIT_ERROR, "cannot read free space: " + (exc.strerror or str(exc)), path=target)
    return {"path": target, "total_bytes": total, "used_bytes": used, "free_bytes": free_bytes, "ts": common.now_iso()}


def run(args) -> dict:
    if args.cmd == "check":
        return check()
    if args.cmd == "free":
        return free(getattr(args, "path", None))
    raise CorecleanerError(common.EXIT_USAGE, "platform_info does not serve %r" % args.cmd)
