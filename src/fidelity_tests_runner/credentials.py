"""The key pair an emulator started with ``--auth on`` minted, found by its port.

Before it listens, the emulator writes the pair to
``<HOME>/<its home dir>/<port>/emulator_credentials``; the home dir is per emulator
(``.emulator``, ``.aws/emulator``, ...). The lookup searches :data:`key_home`, the HOME the
emulator was given, by the endpoint's port.
"""

import errno
import logging
import os
import stat
from pathlib import Path
from urllib.parse import urlsplit

from botocore.credentials import Credentials

from fidelity_tests_runner.target import is_loopback_endpoint

logger = logging.getLogger("fidelity_tests_runner.credentials")

#: The HOME emulators write their key files under; None means this process's own HOME.
key_home: Path | None = None

#: Prefixes of access keys AWS issues; an emulator's key file never holds one.
AWS_KEY_PREFIXES = ("AKIA", "ASIA", "AIDA", "AROA", "AGPA", "ANPA", "ANVA", "APKA", "ABIA", "ACCA")

#: The file an ``--auth on`` emulator writes its key pair to.
KEY_FILE = "emulator_credentials"


def credentials_file(port: int, home: Path) -> Path | None:
    """The newest key file an emulator on ``port`` wrote under ``home``, resolved, or None."""
    return published_file(port, home, KEY_FILE)


def published_file(port: int, home: Path, name: str) -> Path | None:
    """The newest ``<home dir>/<port>/<name>`` an emulator wrote under ``home``, resolved, or None.

    A candidate that resolves outside ``home`` or cannot be stat-ed (a dangling link) is skipped:
    an emulator in a sandbox could otherwise point it at a host secret. So is one this user does
    not own, or that another user could have written (the file or a directory up to ``home``).
    """
    pattern = f"{port}/{name}"
    found = [*home.glob(f"*/{pattern}"), *home.glob(f"*/*/{pattern}")]
    return max(filter(None, (_inside(path, home) for path in found)), key=_mtime, default=None)


def _inside(path: Path, home: Path) -> Path | None:
    real = path.resolve()
    root = home.resolve()
    if not (real.is_relative_to(root) and real.is_file()):
        return None
    return real if all(map(_trusted, [real, *_parents_to(real, root)])) else None


def _parents_to(path: Path, root: Path) -> list[Path]:
    """``path``'s directories up to and including ``root``."""
    return [p for p in path.parents if p.is_relative_to(root)]


def _trusted(path: Path) -> bool:
    """Whether ``path`` exists and is :func:`_owned`."""
    try:
        return _owned(path.stat())
    except OSError:
        return False


def _owned(st: os.stat_result) -> bool:
    """Owned by this user and writable by nobody else."""
    return not _untrusted_reason(st)


def _untrusted_reason(st: os.stat_result) -> str:
    """Why :func:`_owned` fails for ``st``, or the empty string."""
    if st.st_uid != os.getuid():
        return f"owned by uid {st.st_uid}, not {os.getuid()}"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return "writable by group or other"
    return ""


def read_published(path: Path) -> str:
    """The text of a file an emulator published, read through one descriptor opened and checked.

    The file and its directory are opened without following a link and checked with ``fstat``.
    """
    parent = _open_owned(path.parent, os.O_DIRECTORY)
    try:
        fd = _open_owned(path, os.O_NONBLOCK, dir_fd=parent, regular=True)
    finally:
        os.close(parent)
    with open(fd, encoding="utf-8") as file:
        return file.read()


def _open_owned(path: Path, flags: int, dir_fd: int | None = None, regular: bool = False) -> int:
    """A descriptor for ``path`` (its name under ``dir_fd``), not followed if a link, and owned.

    Raises PermissionError naming the full path and the reason.
    """
    name = path.name if dir_fd is not None else path
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | flags, dir_fd=dir_fd)
    except OSError as exc:
        # O_NOFOLLOW refuses a link with ELOOP (EMLINK on FreeBSD), or ENOTDIR under O_DIRECTORY.
        if exc.errno in (errno.ELOOP, errno.EMLINK, errno.ENOTDIR) and path.is_symlink():
            raise PermissionError(f"{path} is a link") from exc
        if exc.errno == errno.ENOTDIR and not regular:
            raise PermissionError(f"{path} is not a directory") from exc
        raise
    try:
        st = os.fstat(fd)
        reason = _untrusted_reason(st)
        if regular and not stat.S_ISREG(st.st_mode):
            reason = "not a regular file"
    except BaseException:
        os.close(fd)
        raise
    if not reason:
        return fd
    os.close(fd)
    raise PermissionError(f"{path} is {reason}")


def _mtime(path: Path) -> float:
    """``path``'s modification time; a file gone since the lookup sorts first and fails its read."""
    try:
        return path.stat().st_mtime
    except OSError:
        return float("-inf")


def read_key_file(path: Path) -> Credentials:
    """The ``aws_access_key_id`` / ``aws_secret_access_key`` pair in ``path``.

    Raises ValueError for a file that cannot be read, names no key pair, or holds an AWS-issued
    key: an emulator's key file is never an AWS credentials file.
    """
    try:
        text = read_published(path)
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    sections = [line.strip() for line in text.splitlines() if line.strip().startswith("[")]
    if sections not in ([], ["[default]"]):
        raise ValueError(f"{path} names AWS profiles; pass the emulator's own key file")
    pairs = [line.partition("=") for line in text.splitlines() if "=" in line]
    fields = {name.strip(): value.strip() for name, _, value in pairs}
    if len(fields) != len(pairs):
        raise ValueError(f"{path} names a key twice; pass the emulator's own key file")
    key, secret = fields.get("aws_access_key_id"), fields.get("aws_secret_access_key")
    if not key or not secret:
        raise ValueError(f"{path} names no key pair")
    if key.startswith(AWS_KEY_PREFIXES) or fields.get("aws_session_token"):
        raise ValueError(f"{path} holds an AWS-issued access key; pass the emulator's own key file")
    return Credentials(key, secret)


def minted_credentials(endpoint: str) -> Credentials | None:
    """The keys the loopback emulator at ``endpoint`` minted, or None when it wrote none.

    Raises ValueError for a key file that cannot be read or names no key pair.
    """
    port = urlsplit(endpoint).port
    home = key_home or Path.home()
    path = credentials_file(port, home) if port and is_loopback_endpoint(endpoint) else None
    if path is None:
        logger.info("found no key file for %s", endpoint)
        return None
    return read_key_file(path)
