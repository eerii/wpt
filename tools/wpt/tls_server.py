# mypy: allow-untyped-defs

"""Download and install the rustls TLS test server used by `wpt serve`/`wpt run`.

The server is distributed as a prebuilt static binary per platform in a GitHub
release (see ``DEFAULT_BASE_URL``), with a sibling ``.sha256sum`` asset. This
module is invoked explicitly via ``wpt install tls-server`` and implicitly when
``--tls-server``/``--enable-tls-server`` is passed without a local binary.
"""

import logging
import os
import platform
import sys

from .utils import get, get_download_to_descriptor, sha256sum, untar, unzip

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
        return override if os.path.isfile(override) else None
    candidates = []
    if venv_path:
        candidates.append(os.path.join(venv_path, "bin", binary_name()))
    candidates.append(os.path.join(venv_bin_dir(), binary_name()))
    candidates.append(dev_binary())
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def download(dest, version=None, base_url=None, logger=None):
    """Download and unpack the server into ``dest``; return the binary path."""
    logger = logger or logging.getLogger("tls_server")
    base = (base_url or DEFAULT_BASE_URL).rstrip("/")
    if version is not None:
        base = base.rsplit("/download/", 1)[0] + "/download/v%s" % version
    asset, ext = asset_info(version)
    url = "%s/%s" % (base, asset)

    os.makedirs(dest, exist_ok=True)
    archive = os.path.join(dest, asset)
    logger.info("Downloading %s", url)
    with open(archive, "wb") as archive_file:
        get_download_to_descriptor(archive_file, url)

    expected = get(url + ".sha256sum").text.strip().split()[0]
    actual = sha256sum(archive)
    if actual != expected:
        os.unlink(archive)
        raise RuntimeError("checksum mismatch for %s: expected %s, got %s"
                           % (asset, expected, actual))

    with open(archive, "rb") as archive_file:
        if ext == ".zip":
            unzip(archive_file, dest)
        else:
            untar(archive_file, dest)
    os.unlink(archive)

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
