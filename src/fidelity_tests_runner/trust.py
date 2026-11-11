"""TLS trust for an https emulator on loopback: the CA it publishes beside its keys.

The CA is published at ``<HOME>/<its home dir>/<port>/ca.pem``, found like the keys, and trusted
beside certifi's CAs for loopback endpoints only. The chain a listener presents is never trusted.
"""

import atexit
import shutil
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import certifi

from fidelity_tests_runner import credentials
from fidelity_tests_runner.target import is_loopback_endpoint

#: The variables a CLI or IaC tool reads its trust bundle from: botocore, requests, OpenSSL and Go,
#: curl, and Node.
BUNDLE_ENV = (
    "AWS_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
)

#: The CA an emulator publishes beside its key file, for a leaf that CA issued.
CA_FILE = "ca.pem"

#: An emulator's TLS trust: its published CA verifies the handshake (``TLS_PINNED``); it published
#: no CA (``TLS_UNPUBLISHED``); reading failed (``TLS_UNREAD``); or the bundle does not verify the
#: handshake (``TLS_UNVERIFIABLE``). The last three leave verification as the caller set it.
TLS_PINNED = "pinned"
TLS_UNPUBLISHED = "unpublished"
TLS_UNREAD = "unread"
TLS_UNVERIFIABLE = "unverifiable"

_HANDSHAKE_TIMEOUT_S = 5.0
#: How long a verified CA stands for its endpoint: one handshake serves a run's calls. A CA file
#: that changed (an emulator restarted on the port) is read and verified again at once.
_PIN_TTL_S = 60.0
_lock = threading.Lock()
_bundles: dict[str, str] = {}
_pins: dict[tuple, tuple[float, bool | str, str]] = {}
_dir: Path | None = None


def emulator_tls(
    endpoint: str, verify_ssl: bool | str, *, ca_port: int | None = None
) -> tuple[bool | str, str]:
    """``(verify, status)`` for clients aimed at ``endpoint``; a caller's CA bundle wins.

    An https loopback endpoint is ``TLS_PINNED`` once the CA the emulator published under
    ``ca_port`` (by default the endpoint's own port) verifies a handshake with the hostname
    checked; else ``verify_ssl`` stands (``TLS_UNPUBLISHED``, ``TLS_UNREAD``,
    ``TLS_UNVERIFIABLE``). Others get no status.
    """
    if (isinstance(verify_ssl, str) and verify_ssl) or not endpoint:
        return verify_ssl, ""
    url = urlsplit(endpoint)
    if url.scheme != "https" or not is_loopback_endpoint(endpoint):
        return verify_ssl, ""
    address = (url.hostname or "", url.port or 443)
    try:
        path = _published_ca_file(ca_port or address[1])
        if path is None:
            return verify_ssl, TLS_UNPUBLISHED
        key = (address, verify_ssl, _identity(path))
        with _lock:
            pinned = _pins.get(key)
        if pinned and time.monotonic() - pinned[0] < _PIN_TTL_S:
            return pinned[1], pinned[2]
        bundle = _bundle(credentials.read_published(path).strip())
        verify_handshake(address, bundle)
        verified: tuple[bool | str, str] = (bundle, TLS_PINNED)
    except ssl.SSLError:
        verified = (verify_ssl, TLS_UNVERIFIABLE)
    except (OSError, ValueError):
        return verify_ssl, TLS_UNREAD
    with _lock:
        _pins[key] = (time.monotonic(), *verified)
    return verified


def _published_ca_file(port: int) -> Path | None:
    """The CA file the emulator on ``port`` published under the key home, or None."""
    return credentials.published_file(port, credentials.key_home or Path.home(), CA_FILE)


def _identity(path: Path) -> tuple[int, int, int, int]:
    """What changes when the file is rewritten or replaced: device, inode, size, mtime."""
    st = path.stat()
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def verify_handshake(address: tuple[str, int], bundle: str) -> None:
    """Complete a verified TLS handshake with ``address`` against ``bundle``, or raise.

    Python's default context (strict from 3.13, as ``requests``) with no partial chain (as
    botocore) and the hostname checked: what every client handed the bundle requires. Raises
    ``ssl.SSLCertVerificationError`` when the bundle does not verify the chain.
    """
    context = ssl.create_default_context(cafile=bundle)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_flags &= ~ssl.VERIFY_X509_PARTIAL_CHAIN
    host = address[0].strip("[]")
    with socket.create_connection(address, timeout=_HANDSHAKE_TIMEOUT_S) as sock:
        with context.wrap_socket(sock, server_hostname=host):
            pass


def emulator_verify(
    endpoint: str, verify_ssl: bool | str, *, ca_port: int | None = None
) -> bool | str:
    """What a client aimed at ``endpoint`` verifies TLS against (:func:`emulator_tls`)."""
    return emulator_tls(endpoint, verify_ssl, ca_port=ca_port)[0]


def union_bundle(first: bool | str, second: str) -> str:
    """A bundle trusting what both bundles trust; ``second`` alone when ``first`` is not one."""
    if not (isinstance(first, str) and first) or first == second:
        return second
    with _lock:
        own = {path: pem for pem, path in _bundles.items()}
    pems = [own.get(path) or Path(path).read_text(encoding="utf-8") for path in (first, second)]
    return _bundle("\n".join(pem.strip() for pem in pems))


def bundle_env(verify: bool | str) -> dict[str, str]:
    """``BUNDLE_ENV`` pointed at ``verify`` when it is a CA bundle, else nothing."""
    return dict.fromkeys(BUNDLE_ENV, verify) if isinstance(verify, str) and verify else {}


def _bundle(pem: str) -> str:
    """A file holding certifi's CAs and ``pem``, written once per distinct set of certificates."""
    global _dir
    with _lock:
        if pem not in _bundles:
            if _dir is None:
                _dir = Path(tempfile.mkdtemp(prefix="fidelity-tests-trust-"))
                atexit.register(shutil.rmtree, _dir, ignore_errors=True)
            path = _dir / f"bundle-{len(_bundles)}.pem"
            system = Path(certifi.where()).read_text(encoding="utf-8")
            path.write_text(f"{system.rstrip()}\n{pem.strip()}\n", encoding="utf-8")
            _bundles[pem] = str(path)
        return _bundles[pem]
