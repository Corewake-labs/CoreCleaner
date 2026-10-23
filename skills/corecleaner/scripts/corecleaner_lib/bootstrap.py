"""Install the pinned dua-cli into a user directory. (T8; subcommand `bootstrap`)

The only network access in the project. Never sudo, never PATH or profile edits. Pins live in
../references/pins.tsv (target, asset URL, sha256, version, bytes) and are the single source of truth.

run(args): args.yes (bool). Returns bootstrap(args.yes).

bootstrap(yes) -> dict
  1. dua >= 2.43.0 already on PATH (or at the install destination): action "skip", nothing else runs.
  2. No pin for this OS/arch: exit 10 (error_details lists the supported targets).
  3. Without yes: action "needs_consent". Describes only (source, version, sha256, destination, bytes,
     whether an older dua would be replaced) and touches nothing: no network, no files, no process
     besides `dua --version` probes. The agent asks the user, then calls again with --yes.
  4. With yes: download over HTTPS into a fresh temp dir inside the state dir (offline/unreachable
     -> exit 11), compare sha256 BEFORE opening the archive (mismatch -> exit 20, temp dir deleted,
     nothing executed), extract the single dua binary by streaming one regular member (no archive path
     ever reaches the filesystem), self-test the staged binary, then install it atomically.
Install destination: ~/.local/bin/dua (macOS/Linux, mode 0o755) or <state dir>/bin/dua.exe (Windows,
beta/untested). An existing dua there is replaced only when it is an older working dua; a symlink,
a directory or an unknown file is refused. The self-test is `dua --version` (must equal the pin) plus,
on macOS, a 20 MiB fixture with 3 `cp -c` clones and 1 hardlink that must total exactly 20 MiB with
--deduplicate-apfs-clones; a failed self-test installs nothing. The only deletions are inside the
temp dir this module created in the state dir.
Result keys (all actions): action, installed, present, needs_consent, path, version, sha256, source,
plus target/destination/bytes/prompt (needs_consent) and selftest/on_path (installed).
"""

from __future__ import annotations

import hashlib
import http.client
import os
import platform
import posixpath
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Dict, Optional, Tuple

from . import common
from .common import CorecleanerError

# --deduplicate-apfs-clones first shipped in 2.43.0; older dua cannot give exact macOS totals.
MIN_DUA = (2, 43, 0)
PINS_FILE = Path(__file__).resolve().parents[2] / "references" / "pins.tsv"
# Widened by tests to reach a loopback server; production only ever speaks https.
_URL_SCHEMES = ("https",)
USER_AGENT = "corecleaner/" + common.VERSION
NET_TIMEOUT = 30
PROBE_TIMEOUT = 20
MAX_BINARY_BYTES = 128 * 1024 * 1024
FIXTURE_BYTES = 20 * 1024 * 1024
_CHUNK = 1 << 16

_OS_TAG = {"macos": "apple-darwin", "linux": "unknown-linux-musl", "windows": "pc-windows-msvc"}
_ARCH_TAG = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64", "amd64": "x86_64"}
_TARGET_RE = re.compile(r"^(aarch64|x86_64)-(apple-darwin|unknown-linux-musl|pc-windows-msvc)$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_DUA_VERSION_RE = re.compile(r"\bdua\s+v?(\d+)\.(\d+)\.(\d+)")
_AGGREGATE_LINE_RE = re.compile(r"^\s*(\d+) b (.+?)\s*$")


@dataclass(frozen=True)
class Pin:
    target: str
    url: str
    sha256: str
    version: str
    size: int

    @property
    def kind(self) -> str:
        return "zip" if "windows" in self.target else "tar.gz"

    @property
    def member(self) -> str:
        return "dua.exe" if "windows" in self.target else "dua"


# ---------------------------------------------------------------- pins

def parse_pins(text: str) -> Dict[str, Pin]:
    """Strict parse of pins.tsv; a malformed row is an error, never skipped."""
    pins: Dict[str, Pin] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue

        def bad(why: str) -> CorecleanerError:
            return CorecleanerError(common.EXIT_ERROR, "pins.tsv line %d: %s" % (number, why))

        cols = line.split("\t")
        if len(cols) != 5:
            raise bad("expected 5 tab-separated columns")
        target, url, sha256, version, size = (c.strip() for c in cols)
        if not _TARGET_RE.match(target):
            raise bad("unknown target %r" % target)
        if target in pins:
            raise bad("duplicate target %s" % target)
        if not _SHA_RE.match(sha256):
            raise bad("sha256 must be 64 lowercase hex digits")
        if not _VERSION_RE.match(version):
            raise bad("version must be MAJOR.MINOR.PATCH")
        if not size.isdigit() or int(size) <= 0:
            raise bad("bytes must be a positive integer")
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in _URL_SCHEMES or not parts.netloc:
            raise bad("url must be %s" % "/".join(_URL_SCHEMES))
        ext = "zip" if "windows" in target else "tar.gz"
        if posixpath.basename(parts.path) != "dua-v%s-%s.%s" % (version, target, ext):
            raise bad("asset name does not match version and target")
        pins[target] = Pin(target, url, sha256, version, int(size))
    if not pins:
        raise CorecleanerError(common.EXIT_ERROR, "pins.tsv has no rows")
    return pins


def load_pins() -> Dict[str, Pin]:
    try:
        text = PINS_FILE.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise CorecleanerError(common.EXIT_ERROR, "cannot read pins.tsv: %s" % exc, path=str(PINS_FILE))
    return parse_pins(text)


def select_pin(pins: Dict[str, Pin], os_name: str, machine: str) -> Pin:
    arch, os_tag = _ARCH_TAG.get(machine.lower()), _OS_TAG.get(os_name)
    pin = pins.get("%s-%s" % (arch, os_tag)) if arch and os_tag else None
    if pin is None:
        raise CorecleanerError(
            common.EXIT_UNSUPPORTED_ARCH,
            "no pinned dua build for %s/%s" % (os_name, machine),
            os=os_name,
            machine=machine,
            supported=sorted(pins),
            hint="Install dua >= %s yourself (https://github.com/Byron/dua-cli) or use scan's basic mode."
            % ".".join(map(str, MIN_DUA)),
        )
    return pin


# ---------------------------------------------------------------- platform and paths

def _os_name() -> str:
    if sys.platform == "darwin":
        return "macos"
    if sys.platform == "win32":
        return "windows"
    return "linux" if sys.platform.startswith("linux") else sys.platform


def _binary_name(os_name: str) -> str:
    return "dua.exe" if os_name == "windows" else "dua"


def install_dir(os_name: str) -> Path:
    """~/.local/bin on macOS/Linux; <state dir>/bin on Windows. Not created here."""
    if os_name == "windows":
        return common.state_dir() / "bin"
    return Path.home() / ".local" / "bin"


def _dir_on_path(directory: Path) -> bool:
    want = os.path.normcase(os.path.realpath(str(directory)))
    entries = os.environ.get("PATH", "").split(os.pathsep)
    return any(e and os.path.normcase(os.path.realpath(e)) == want for e in entries)


# ---------------------------------------------------------------- probing an existing dua

def parse_version(text: str) -> Optional[Tuple[int, ...]]:
    match = _DUA_VERSION_RE.search(text or "")
    return tuple(int(g) for g in match.groups()) if match else None


def probe_version(binary: str) -> Optional[str]:
    """`<binary> --version` -> "2.46.0", or None when it does not run or is not dua."""
    try:
        proc = subprocess.run(
            [binary, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    parsed = parse_version(proc.stdout) if proc.returncode == 0 else None
    return ".".join(map(str, parsed)) if parsed else None


def _find_present(dest: Path) -> Optional[dict]:
    candidates = []
    on_path = shutil.which("dua")
    if on_path:
        candidates.append(on_path)
    if dest.is_file() and str(dest) not in candidates:
        candidates.append(str(dest))
    for candidate in candidates:
        version = probe_version(candidate)
        if version and (parse_version("dua " + version) or ()) >= MIN_DUA:
            return {"path": candidate, "version": version}
    return None


def _inspect_destination(dest: Path) -> Optional[str]:
    """Version of an older dua that may be replaced; None when dest is free; refuse anything else."""
    if dest.is_symlink():
        raise CorecleanerError(common.EXIT_ERROR, "install destination is a symlink; refusing", path=str(dest))
    if not dest.exists():
        return None
    version = probe_version(str(dest)) if dest.is_file() else None
    if version is None:
        raise CorecleanerError(
            common.EXIT_ERROR,
            "install destination exists and is not a working dua; refusing to overwrite it",
            path=str(dest),
        )
    return version


# ---------------------------------------------------------------- download

class _SchemeGuardRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme not in _URL_SCHEMES:
            raise urllib.error.HTTPError(newurl, code, "redirect to a disallowed scheme", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _network_error(pin: Pin, exc: BaseException) -> CorecleanerError:
    reason = getattr(exc, "reason", None) or exc
    hint = "In an agent sandbox, ask the user to approve running this command with network access."
    if isinstance(reason, ssl.SSLCertVerificationError):
        hint = "TLS certificate verification failed; python.org builds need 'Install Certificates.command'."
    return CorecleanerError(
        common.EXIT_NO_NETWORK,
        "cannot download dua (offline, blocked or sandboxed): %s" % reason,
        url=pin.url,
        hint=hint,
    )


def _download(pin: Pin, dest: Path) -> Tuple[str, int]:
    """Stream pin.url to dest; return (sha256 hex, byte count). Never reads the archive."""
    limit = max(pin.size * 2, 1 << 20)
    digest, total = hashlib.sha256(), 0
    request = urllib.request.Request(pin.url, headers={"User-Agent": USER_AGENT})
    opener = urllib.request.build_opener(_SchemeGuardRedirect)
    try:
        with opener.open(request, timeout=NET_TIMEOUT) as resp, open(dest, "wb") as out:
            while True:
                chunk = resp.read(_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise CorecleanerError(
                        common.EXIT_HASH_MISMATCH,
                        "download exceeds the pinned size; aborted, nothing was run",
                        url=pin.url,
                        pinned_bytes=pin.size,
                    )
                digest.update(chunk)
                out.write(chunk)
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            error = CorecleanerError(
                common.EXIT_ERROR,
                "pinned asset not found (HTTP %d); pins.tsv is outdated" % exc.code,
                url=pin.url,
            )
        else:
            error = _network_error(pin, exc)
        exc.close()
        raise error
    except (
        urllib.error.URLError,
        http.client.HTTPException,
        ConnectionError,
        socket.timeout,
        TimeoutError,
        ssl.SSLError,
    ) as exc:
        raise _network_error(pin, exc)
    except OSError as exc:
        raise CorecleanerError(common.EXIT_ERROR, "cannot write the download: %s" % exc.strerror, path=str(dest))
    return digest.hexdigest(), total


# ---------------------------------------------------------------- extraction

def _is_member(path: str, name: str) -> bool:
    parts = [p for p in path.replace("\\", "/").split("/") if p not in ("", ".")]
    return bool(parts) and ".." not in parts and len(parts) <= 2 and parts[-1] == name


def _write_member(src: IO[bytes], dest: Path, declared: int) -> None:
    if declared > MAX_BINARY_BYTES:
        raise CorecleanerError(common.EXIT_ERROR, "archive member is implausibly large; refusing")
    written = 0
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(str(dest), flags, 0o755), "wb") as out:
        while True:
            chunk = src.read(_CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_BINARY_BYTES:
                raise CorecleanerError(common.EXIT_ERROR, "archive member is implausibly large; refusing")
            out.write(chunk)
    os.chmod(str(dest), 0o755)


def _extract_binary(archive: Path, pin: Pin, dest: Path) -> None:
    """Copy the one regular `dua`/`dua.exe` member to dest; nothing else leaves the archive."""
    try:
        if pin.kind == "zip":
            with zipfile.ZipFile(str(archive)) as zf:
                hits = [
                    i
                    for i in zf.infolist()
                    if not i.is_dir()
                    and _is_member(i.filename, pin.member)
                    and (i.external_attr >> 16) & 0o170000 != 0o120000
                ]
                if len(hits) != 1:
                    raise CorecleanerError(common.EXIT_ERROR, "archive must hold exactly one %s" % pin.member)
                with zf.open(hits[0]) as src:
                    _write_member(src, dest, hits[0].file_size)
        else:
            with tarfile.open(str(archive), "r:gz") as tf:
                hits = [m for m in tf.getmembers() if m.isreg() and _is_member(m.name, pin.member)]
                if len(hits) != 1:
                    raise CorecleanerError(common.EXIT_ERROR, "archive must hold exactly one %s" % pin.member)
                src = tf.extractfile(hits[0])
                if src is None:
                    raise CorecleanerError(common.EXIT_ERROR, "cannot read %s from archive" % pin.member)
                with src:
                    _write_member(src, dest, hits[0].size)
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, zlib.error, OSError) as exc:
        raise CorecleanerError(common.EXIT_ERROR, "cannot extract dua from the archive: %s" % exc)


# ---------------------------------------------------------------- self-test

def _aggregate_total(text: str) -> Optional[int]:
    for line in reversed(text.splitlines()):
        match = _AGGREGATE_LINE_RE.match(line)
        if match and match.group(2) == "total":
            return int(match.group(1))
    return None


def _clone_check(binary: Path, workdir: Path) -> dict:
    """macOS: 1 file + 3 APFS clones + 1 hardlink must total exactly one file with dedup on."""
    fixture = workdir / "clone-fixture"
    fixture.mkdir(mode=0o700)
    base = fixture / "base.bin"
    with open(str(base), "wb") as fh:
        for _ in range(FIXTURE_BYTES >> 20):
            fh.write(os.urandom(1 << 20))
    for index in (1, 2, 3):
        cloned = subprocess.run(
            ["/bin/cp", "-c", str(base), str(fixture / ("clone%d.bin" % index))],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if cloned.returncode != 0:
            return {"status": "skipped", "reason": "this volume does not support APFS clones (cp -c failed)"}
    os.link(str(base), str(fixture / "hardlink.bin"))
    proc = subprocess.run(
        [str(binary), "aggregate", "-f", "bytes", "--deduplicate-apfs-clones", str(fixture)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=120,
    )
    total = _aggregate_total(proc.stdout)
    if proc.returncode != 0 or total != FIXTURE_BYTES:
        raise CorecleanerError(
            common.EXIT_ERROR,
            "self-test failed: clone fixture totals %s bytes, expected exactly %d" % (total, FIXTURE_BYTES),
            exit_status=proc.returncode,
            stderr=(proc.stderr or "")[-300:],
        )
    return {"status": "ok", "expected_bytes": FIXTURE_BYTES, "total_bytes": total}


def _selftest(binary: Path, pin: Pin, os_name: str, workdir: Path) -> dict:
    version = probe_version(str(binary))
    if version != pin.version:
        raise CorecleanerError(
            common.EXIT_ERROR,
            "self-test failed: `dua --version` gave %s, pinned %s" % (version, pin.version),
        )
    clone = _clone_check(binary, workdir) if os_name == "macos" else {"status": "not_applicable"}
    return {"version": version, "clone_check": clone}


# ---------------------------------------------------------------- install

def _install(staged: Path, dest: Path) -> None:
    """Copy next to dest, then rename over it. A failure may leave the sibling temp file; it is
    reported, never deleted, because dest's directory belongs to the user."""
    temp = ""
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(dir=str(dest.parent), prefix=".dua-", suffix=".tmp")
        with os.fdopen(fd, "wb") as out, open(str(staged), "rb") as src:
            shutil.copyfileobj(src, out)
        os.chmod(temp, 0o755)
        os.replace(temp, str(dest))
    except OSError as exc:
        raise CorecleanerError(
            common.EXIT_ERROR,
            "cannot install dua into %s: %s" % (dest.parent, exc.strerror or exc),
            leftover=temp or None,
        )


def _discard_work(work: Path, root: Path) -> None:
    """Delete the temp dir this module made; refuses anything that is not a direct dua-* child of root."""
    real, real_root = os.path.realpath(str(work)), os.path.realpath(str(root))
    if os.path.dirname(real) != real_root or not os.path.basename(real).startswith("dua-"):
        common.log("not removing unexpected temp path " + real)
        return
    shutil.rmtree(real, ignore_errors=True)
    if os.path.exists(real):
        common.log("could not fully remove temp dir " + real)


# ---------------------------------------------------------------- entry points

def _result(action: str, **fields: Any) -> dict:
    out = {
        "action": action,
        "installed": False,
        "present": False,
        "needs_consent": False,
        "path": None,
        "version": None,
        "sha256": None,
        "source": None,
    }
    out.update(fields)
    return out


def _describe(pin: Pin, dest: Path, replaced: Optional[str]) -> dict:
    prompt = "Install dua %s (disk analyzer) from %s (sha256 %s, %.1f MB) into %s?" % (
        pin.version,
        pin.url,
        pin.sha256,
        pin.size / 1e6,
        dest,
    )
    if replaced:
        prompt += " This replaces the existing dua %s there." % replaced
    return _result(
        "needs_consent",
        needs_consent=True,
        version=pin.version,
        sha256=pin.sha256,
        source=pin.url,
        target=pin.target,
        destination=str(dest),
        bytes=pin.size,
        replaces_existing=replaced is not None,
        existing_version=replaced,
        prompt=prompt,
    )


def _bootstrap(yes: bool, os_name: str, machine: str) -> dict:
    dest = install_dir(os_name) / _binary_name(os_name)
    present = _find_present(dest)
    if present:
        return _result(
            "skip",
            present=True,
            path=present["path"],
            version=present["version"],
            reason="dua %s already available (>= %s)" % (present["version"], ".".join(map(str, MIN_DUA))),
        )
    pin = select_pin(load_pins(), os_name, machine)
    replaced = _inspect_destination(dest)
    if not yes:
        return _describe(pin, dest, replaced)

    tmp_root = common.state_subdir("tmp")
    work = Path(tempfile.mkdtemp(prefix="dua-", dir=str(tmp_root)))
    try:
        archive = work / ("download." + pin.kind)
        common.log("downloading " + pin.url)
        actual, total = _download(pin, archive)
        if actual != pin.sha256:
            raise CorecleanerError(
                common.EXIT_HASH_MISMATCH,
                "sha256 mismatch; the download was discarded and nothing was run",
                expected=pin.sha256,
                actual=actual,
                bytes=total,
                url=pin.url,
            )
        common.log("sha256 verified")
        staged = work / pin.member
        _extract_binary(archive, pin, staged)
        selftest = _selftest(staged, pin, os_name, work)
        _install(staged, dest)
    finally:
        _discard_work(work, tmp_root)

    if probe_version(str(dest)) != pin.version:
        raise CorecleanerError(
            common.EXIT_ERROR, "installed dua does not report %s when run from its destination" % pin.version,
            path=str(dest),
        )
    on_path = _dir_on_path(dest.parent)
    return _result(
        "installed",
        installed=True,
        present=True,
        path=str(dest),
        version=pin.version,
        sha256=pin.sha256,
        source=pin.url,
        target=pin.target,
        destination=str(dest),
        bytes=pin.size,
        replaced_version=replaced,
        selftest=selftest,
        on_path=on_path,
        note=None if on_path else "%s is not on PATH; call dua by the absolute path in `path`" % dest.parent,
    )


def bootstrap(yes: bool, decline: bool = False) -> dict:
    """--decline records the user's no in settings.json (`dua: declined`) so the question is not asked again."""
    if decline:
        out = _bootstrap(False, _os_name(), platform.machine())
        out.update(action="declined", needs_consent=False, prompt=None)
        common.write_settings(dua="declined")
        return out
    out = _bootstrap(bool(yes), _os_name(), platform.machine())
    if out.get("action") == "installed" or (out.get("present") and out.get("installed")):
        common.write_settings(dua="installed")
    return out


def run(args: Any) -> dict:
    return bootstrap(bool(getattr(args, "yes", False)), bool(getattr(args, "decline", False)))
