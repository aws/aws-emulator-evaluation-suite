"""An https emulator is authenticated by the CA it publishes, never by the chain it presents.

A local process that binds the emulator's port first presents a chain of its own; that chain is
never trusted.
"""

import datetime
import ipaddress
import socket
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from fidelity_tests_runner import credentials, trust
from fidelity_tests_runner.context import FIXED_CREDS, Context


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject: str, key, issuer: str, issuer_key, *, ca: bool, san: bool) -> x509.Certificate:
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def pki(tmp_path):
    """A CA, a leaf it issued, and a self-signed CA:TRUE certificate nobody published."""
    ca_key, leaf_key, rogue_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    ca = _cert("emulator CA", ca_key, "emulator CA", ca_key, ca=True, san=False)
    leaf = _cert("emulator", leaf_key, "emulator CA", ca_key, ca=False, san=True)
    rogue = _cert("localhost", rogue_key, "localhost", rogue_key, ca=True, san=True)

    def files(name: str, cert: x509.Certificate, key) -> tuple[Path, Path]:
        cert_path, key_path = tmp_path / f"{name}.pem", tmp_path / f"{name}.key"
        cert_path.write_text(_pem(cert) + (_pem(ca) if cert is leaf else ""))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return cert_path, key_path

    return {
        "ca": _pem(ca),
        "leaf": files("leaf", leaf, leaf_key),
        "rogue": files("rogue", rogue, rogue_key),
    }


@pytest.fixture
def listener():
    """Start a loopback TLS listener presenting ``(cert, key)``; yields a starter of them."""
    servers = []

    def start(chain: tuple[Path, Path]) -> int:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*map(str, chain))
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(8)
        stop = threading.Event()

        def serve():
            sock.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                except OSError:
                    continue
                try:
                    with context.wrap_socket(conn, server_side=True) as tls:
                        tls.recv(1)
                except (OSError, ssl.SSLError):
                    pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        servers.append((sock, stop, thread))
        return sock.getsockname()[1]

    yield start
    for sock, stop, thread in servers:
        stop.set()
        thread.join(2)
        sock.close()


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setattr(credentials, "key_home", home)
    return home


def _publish(home: Path, port: int, pem: str) -> None:
    folder = home / ".aws" / "emulator" / str(port)
    folder.mkdir(parents=True, mode=0o700)
    (folder / trust.CA_FILE).write_text(pem)
    (folder / trust.CA_FILE).chmod(0o600)


def test_a_published_ca_that_issued_the_leaf_pins_the_endpoint(pki, listener, home):
    port = listener(pki["leaf"])
    _publish(home, port, pki["ca"])
    verify, status = trust.emulator_tls(f"https://127.0.0.1:{port}", True)
    assert status == trust.TLS_PINNED and isinstance(verify, str)
    assert pki["ca"].strip() in Path(verify).read_text()


def test_a_listener_presenting_its_own_ca_with_none_published_is_not_trusted(pki, listener, home):
    port = listener(pki["rogue"])
    assert trust.emulator_tls(f"https://127.0.0.1:{port}", True) == (True, trust.TLS_UNPUBLISHED)


def test_a_listener_whose_chain_the_published_ca_did_not_issue_is_not_trusted(pki, listener, home):
    """Another local process bound the port first: the published CA does not verify it."""
    port = listener(pki["rogue"])
    _publish(home, port, pki["ca"])
    assert trust.emulator_tls(f"https://127.0.0.1:{port}", True) == (
        True,
        trust.TLS_UNVERIFIABLE,
    )


def test_another_listener_is_verified_against_the_ca_published_for_the_endpoint(
    pki, listener, home
):
    endpoint_port, issued_port, rogue_port = (
        listener(pki["leaf"]),
        listener(pki["leaf"]),
        listener(pki["rogue"]),
    )
    _publish(home, endpoint_port, pki["ca"])
    ctx = Context(f"https://127.0.0.1:{endpoint_port}", creds=FIXED_CREDS)
    pinned = ctx.http_verify
    assert isinstance(pinned, str)
    ctx._trust_listener(f"https://127.0.0.1:{rogue_port}/x")
    assert ctx.http_verify == pinned
    ctx._trust_listener(f"https://127.0.0.1:{issued_port}/x")
    assert isinstance(ctx.http_verify, str)


def test_every_tls_context_refuses_versions_below_1_2():
    """Each TLS context the trust module builds has TLS 1.2 as its floor, whatever the default."""
    import inspect

    from fidelity_tests_runner import trust

    source = inspect.getsource(trust)
    contexts = source.count("ssl.SSLContext(") + source.count("ssl.create_default_context(")
    assert contexts and source.count("minimum_version = ssl.TLSVersion.TLSv1_2") == contexts


def test_a_verified_ca_is_reused_until_its_file_changes(pki, listener, home, monkeypatch):
    port = listener(pki["leaf"])
    _publish(home, port, pki["ca"])
    handshakes = []
    real = trust.verify_handshake
    monkeypatch.setattr(
        trust,
        "verify_handshake",
        lambda address, bundle: handshakes.append(1) or real(address, bundle),
    )
    endpoint = f"https://127.0.0.1:{port}"
    first = trust.emulator_tls(endpoint, True)
    assert trust.emulator_tls(endpoint, True) == first and len(handshakes) == 1
    ca = home / ".aws" / "emulator" / str(port) / trust.CA_FILE
    ca.write_text(pki["ca"] + "\n")  # an emulator restarted on the port published again
    assert trust.emulator_tls(endpoint, True)[1] == trust.TLS_PINNED and len(handshakes) == 2


def test_a_ca_file_that_is_a_link_is_not_trusted(pki, listener, home, tmp_path):
    port = listener(pki["leaf"])
    target = tmp_path / "planted.pem"
    target.write_text(pki["ca"])
    folder = home / ".aws" / "emulator" / str(port)
    folder.mkdir(parents=True, mode=0o700)
    (folder / trust.CA_FILE).symlink_to(target)
    assert trust.emulator_tls(f"https://127.0.0.1:{port}", True) == (True, trust.TLS_UNPUBLISHED)
