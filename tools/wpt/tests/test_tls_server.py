# mypy: allow-untyped-defs

import hashlib
import io
import os
import tarfile
import zipfile

import pytest

from tools.wpt import tls_server


def _make_archive(ext, binary_name):
    stream = io.BytesIO()
    if ext == ".zip":
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(binary_name, b"#!/bin/sh\necho wpt-tls-server\n")
    else:
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            data = b"#!/bin/sh\necho wpt-tls-server\n"
            info = tarfile.TarInfo(binary_name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


class _Response:
    def __init__(self, text):
        self.text = text


def test_asset_info_current_platform():
    asset, ext = tls_server.asset_info()
    assert asset.startswith("wpt-tls-server-")
    assert asset.endswith(ext)
    assert ext in (".tar.gz", ".zip")


def test_find_prefers_env_override(tmp_path, monkeypatch):
    binary = tmp_path / tls_server.binary_name()
    binary.write_text("")
    monkeypatch.setenv("WPT_TLS_SERVER", str(binary))
    assert tls_server.find() == str(binary)


def test_find_broken_env_override_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("WPT_TLS_SERVER", str(tmp_path / "nope"))
    monkeypatch.setattr(tls_server, "venv_bin_dir", lambda: str(tmp_path / "venv"))
    monkeypatch.setattr(tls_server, "dev_binary", lambda: str(tmp_path / "dev"))
    with pytest.raises(RuntimeError, match="not a file"):
        tls_server.find()


def test_find_checks_venv_then_dev(tmp_path, monkeypatch):
    monkeypatch.delenv("WPT_TLS_SERVER", raising=False)
    venv_bin = tmp_path / "venv"
    dev = tmp_path / "dev"
    venv_binary = venv_bin / tls_server.binary_name()
    dev_binary = dev / tls_server.binary_name()
    monkeypatch.setattr(tls_server, "venv_bin_dir", lambda: str(venv_bin))
    monkeypatch.setattr(tls_server, "dev_binary", lambda: str(dev_binary))

    dev.mkdir(parents=True)
    dev_binary.write_text("")
    assert tls_server.find() == str(dev_binary)

    venv_bin.mkdir(parents=True)
    venv_binary.write_text("")
    assert tls_server.find() == str(venv_binary)


def test_download_verifies_checksum_and_extracts(tmp_path, monkeypatch):
    asset, ext = tls_server.asset_info()
    archive = _make_archive(ext, tls_server.binary_name())
    digest = hashlib.sha256(archive).hexdigest()

    monkeypatch.setattr(tls_server, "get_download_to_descriptor",
                        lambda fd, url, **kwargs: fd.write(archive))
    monkeypatch.setattr(tls_server, "get",
                        lambda url: _Response(f"{digest}  {url.rsplit('/', 1)[-1]}"))

    binary = tls_server.download(str(tmp_path))
    assert binary == os.path.join(str(tmp_path), tls_server.binary_name())
    assert os.path.isfile(binary)
    assert os.access(binary, os.X_OK)


def test_download_rejects_bad_checksum(tmp_path, monkeypatch):
    _, ext = tls_server.asset_info()
    archive = _make_archive(ext, tls_server.binary_name())

    monkeypatch.setattr(tls_server, "get_download_to_descriptor",
                        lambda fd, url, **kwargs: fd.write(archive))
    monkeypatch.setattr(tls_server, "get", lambda url: _Response("0" * 64))

    with pytest.raises(RuntimeError, match="checksum mismatch"):
        tls_server.download(str(tmp_path))


def test_download_unsupported_platform(tmp_path, monkeypatch):
    monkeypatch.setattr(tls_server.platform, "uname", lambda: ("Plan9", "x86_64"))
    monkeypatch.setattr(tls_server.platform, "machine", lambda: "x86_64")
    with pytest.raises(RuntimeError, match="no wpt-tls-server build"):
        tls_server.download(str(tmp_path))


def test_pinned_digest_must_be_sha256(monkeypatch):
    monkeypatch.setenv("WPT_TLS_SERVER_SHA256", "not a digest")
    with pytest.raises(RuntimeError, match="not a SHA-256 digest"):
        tls_server.pinned_sha256()


def test_pinned_digest_skips_the_sibling_checksum(tmp_path, monkeypatch):
    _, ext = tls_server.asset_info()
    archive = _make_archive(ext, tls_server.binary_name())
    digest = hashlib.sha256(archive).hexdigest()

    monkeypatch.setattr(tls_server, "get_download_to_descriptor",
                        lambda fd, url, **kwargs: fd.write(archive))
    monkeypatch.setattr(tls_server, "get",
                        lambda url: pytest.fail("should not fetch the checksum"))
    monkeypatch.setenv("WPT_TLS_SERVER_SHA256", digest)

    binary = tls_server.download(str(tmp_path))
    assert os.path.isfile(binary)


def test_malformed_checksum_file(tmp_path, monkeypatch):
    _, ext = tls_server.asset_info()
    archive = _make_archive(ext, tls_server.binary_name())

    monkeypatch.setattr(tls_server, "get_download_to_descriptor",
                        lambda fd, url, **kwargs: fd.write(archive))
    monkeypatch.setattr(tls_server, "get", lambda url: _Response("not a digest"))
    with pytest.raises(RuntimeError, match="does not contain a SHA-256 digest"):
        tls_server.download(str(tmp_path))


def test_extract_rejects_parent_traversal(tmp_path):
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, mode="w:gz") as tar:
        data = b"x"
        info = tarfile.TarInfo("../escaped")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(RuntimeError, match="outside the install directory"):
        tls_server.extract_archive(str(archive), str(tmp_path / "out"), ".tar.gz")


def test_extract_rejects_symlinks(tmp_path):
    archive = tmp_path / "links.tar.gz"
    with tarfile.open(archive, mode="w:gz") as tar:
        info = tarfile.TarInfo("wpt-tls-server")
        info.type = tarfile.SYMTYPE
        info.linkname = "/bin/sh"
        tar.addfile(info)
    with pytest.raises(RuntimeError, match="refusing to extract links"):
        tls_server.extract_archive(str(archive), str(tmp_path / "out"), ".tar.gz")
