# mypy: allow-untyped-defs

"""Download and install the rustls TLS test server used by `wpt serve`/`wpt run`.

The server is distributed as a prebuilt static binary per platform in a GitHub
release (see ``DEFAULT_BASE_URL``), with a sibling ``.sha256sum`` asset. This
module is invoked explicitly via ``wpt install tls-server`` and implicitly when
``--tls-server``/``--enable-tls-server`` is passed without a local binary.

The sibling checksum comes from the same host as the artifact, so it only
detects a corrupted download. Set ``WPT_TLS_SERVER_SHA256`` to pin the digest
out of band when the artifact has to be trusted rather than merely verified.
"""

import logging
import os
import pathlib
import platform
import re
import sys
import tarfile
import tempfile
import zipfile

from .httputils import get, get_download_to_descriptor
from .utils import sha256sum

here = os.path.dirname(__file__)
wpt_root = os.path.abspath(os.path.join(here, os.pardir, os.pardir))

VERSION = "0.1.0"

# Overridable so mirrors/vendors can point at their own artifacts.
DEFAULT_BASE_URL = os.environ.get(
    "WPT_TLS_SERVER_URL",
    f"https://github.com/Igalia/wpt-tls-server/releases/download/v{VERSION}")

# (uname system, machine) -> (rust target triple, archive extension)
TARGETS = {
    ("Linux", "x86_64"): ("x86_64-unknown-linux-musl", ".tar.gz"),
    ("Linux", "aarch64"): ("aarch64-unknown-linux-musl", ".tar.gz"),
    ("Darwin", "x86_64"): ("x86_64-apple-darwin", ".tar.gz"),
    ("Darwin", "arm64"): ("aarch64-apple-darwin", ".tar.gz"),
    ("Windows", "AMD64"): ("x86_64-pc-windows-msvc", ".zip"),
}


def binary_name():
    return "wpt-tls-server.exe" if platform.uname()[0] == "Windows" else "wpt-tls-server"


def asset_info(version=None):
    system = platform.uname()[0]
    machine = platform.machine()
    if (system, machine) not in TARGETS:
        raise RuntimeError("no wpt-tls-server build for %s/%s" % (system, machine))
    target, ext = TARGETS[(system, machine)]
    return "wpt-tls-server-%s-%s%s" % (version or VERSION, target, ext), ext


def venv_bin_dir():
    return os.path.join(wpt_root, f"_venv{sys.version_info[0]}", "bin")


def dev_binary():
    return os.path.join(wpt_root, "tools", "tls", "target", "release", binary_name())


def find(venv_path=None):
    """Return the path to a usable server binary, or None.

    Precedence: ``$WPT_TLS_SERVER`` override, the venv, then a local dev build.
    """
    override = os.environ.get("WPT_TLS_SERVER")
    if override:
        if not os.path.isfile(override):
            raise RuntimeError("WPT_TLS_SERVER points at %s, which is not a file" % override)
        return override
    candidates = []
    if venv_path:
        candidates.append(os.path.join(venv_path, "bin", binary_name()))
    candidates.append(os.path.join(venv_bin_dir(), binary_name()))
    candidates.append(dev_binary())
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def pinned_sha256():
    """A digest supplied out of band, which is the only authenticity check."""
    pinned = os.environ.get("WPT_TLS_SERVER_SHA256")
    if not pinned:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]{64}", pinned.strip()):
        raise RuntimeError("WPT_TLS_SERVER_SHA256 is not a SHA-256 digest")
    return pinned.strip().lower()


def fetch_sha256(url):
    try:
        text = get(url).text
    except Exception as error:
        raise RuntimeError("could not fetch the checksum for %s: %s" % (url, error)) from error
    fields = text.split()
    if not fields or not re.fullmatch(r"[0-9a-fA-F]{64}", fields[0]):
        raise RuntimeError("%s does not contain a SHA-256 digest" % url)
    return fields[0].lower()


def check_archive_names(names):
    for name in names:
        parts = pathlib.PurePosixPath(name).parts
        if name.startswith("/") or ".." in parts:
            raise RuntimeError("refusing to extract %r outside the install directory" % name)


def extract_archive(archive, dest, ext):
    """Unpack, refusing absolute paths, parent traversal, and links."""
    if ext == ".zip":
        with zipfile.ZipFile(archive) as archive_file:
            check_archive_names(archive_file.namelist())
            archive_file.extractall(dest)
        return
    with tarfile.open(archive) as archive_file:
        members = archive_file.getmembers()
        check_archive_names([member.name for member in members])
        if any(member.issym() or member.islnk() for member in members):
            raise RuntimeError("refusing to extract links from %s" % archive)
        # `filter` is only available on 3.12+, where it also drops links.
        kwargs = {"filter": "data"} if sys.version_info >= (3, 12) else {}
        archive_file.extractall(dest, **kwargs)


def download(dest, version=None, base_url=None, logger=None):
    """Download and unpack the server into ``dest``; return the binary path."""
    logger = logger or logging.getLogger("tls_server")
    base = (base_url or DEFAULT_BASE_URL).rstrip("/")
    if version is not None:
        base = base.rsplit("/download/", 1)[0] + "/download/v%s" % version
    asset, ext = asset_info(version)
    url = "%s/%s" % (base, asset)

    expected = pinned_sha256() or fetch_sha256(url + ".sha256sum")

    os.makedirs(dest, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="wpt-tls-server-") as tmp:
        archive = os.path.join(tmp, asset)
        logger.info("Downloading %s", url)
        with open(archive, "wb") as archive_file:
            get_download_to_descriptor(archive_file, url)

        actual = sha256sum(archive)
        if actual != expected:
            raise RuntimeError("checksum mismatch for %s: expected %s, got %s"
                               % (asset, expected, actual))

        extract_archive(archive, dest, ext)

    binary = os.path.join(dest, binary_name())
    if not os.path.isfile(binary):
        raise RuntimeError("%s was not found in %s" % (binary_name(), asset))
    os.chmod(binary, 0o755)
    return binary


def install(venv=None, dest=None, version=None, base_url=None, logger=None):
    if dest is None:
        dest = venv.bin_path if venv is not None else venv_bin_dir()
    return download(dest, version=version, base_url=base_url, logger=logger)


def ensure_installed(venv=None, prompt=True, logger=None):
    """Return a binary path, downloading it if necessary.

    Returns None if the user declines or the binary is unavailable offline.
    """
    logger = logger or logging.getLogger("tls_server")
    path = find(venv.path if venv is not None else None)
    if path:
        return path

    if prompt:
        try:
            answer = input("Download and install wpt-tls-server [Y/n]? ").strip().lower()
        except EOFError:
            answer = "n"
        if answer not in ("", "y"):
            return None

    try:
        return install(venv=venv, logger=logger)
    except Exception as error:  # network/unsupported platform: skip, don't crash
        logger.warning("Could not install wpt-tls-server: %s", error)
        return None
