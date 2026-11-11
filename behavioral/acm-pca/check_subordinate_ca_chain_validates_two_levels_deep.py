"""subordinate-ca-chain-validates-two-levels-deep."""
from __future__ import annotations

import shutil
import socket
import ssl
import tempfile
import threading
import time

from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "subordinate-ca-chain-validates-two-levels-deep"
GROUP = 'data-plane'
SERVICES = ['acm-pca']

_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_SUBORDINATE_TEMPLATE = "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"
_PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
# GENERAL_PURPOSE: short-lived mode must be "the last CA in the certificate hierarchy", so a
# short-lived root signing a subordinate would rely on undocumented leniency.
_USAGE_MODE = "GENERAL_PURPOSE"
_SUB_CA_DAYS = 100
_LEAF_DAYS = 30


def _poll_until(probe, predicate, *, timeout_s=180, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _require_local_crypto():
    """Fail before any create if the local X.509 parser is missing."""
    try:
        from cryptography import x509  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise RequiredToolMissing(["cryptography"]) from exc


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Disable and delete a CA, polling until Status == "DELETED" is observed.

    Billing stops at the DELETED status, not at the delete call.
    """
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + 420
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = _describe(ctx, ca_arn).get("Status")
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if last_status == "DELETED":
            return
        if last_status == "CREATING":
            time.sleep(2)
            continue
        if last_status == "ACTIVE":
            try:
                pca.update_certificate_authority(
                    CertificateAuthorityArn=ca_arn, Status="DISABLED"
                )
            except ClientError as err:
                if err.response["Error"]["Code"] not in (
                    "ResourceNotFoundException", "InvalidStateException", "ConcurrentModificationException"
                ):
                    raise
            time.sleep(2)
            continue
        try:
            pca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn,
                PermanentDeletionTimeInDays=_MIN_DELETION_DAYS,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidStateException", "ConcurrentModificationException"):
                time.sleep(2)
                continue
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(
        f"LEAKED BILLABLE RESOURCE: certificate authority {ca_arn} never reached "
        f"Status=DELETED within 420s (last observed {last_status!r}). It is STILL BILLING at "
        f"the general-purpose rate. Delete it manually: "
        f"UpdateCertificateAuthority(Status='DISABLED') then "
        f"DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
    )


def _create_ca(ctx, scenario, ca_type, prefix):
    """Create a tagged CA and register its teardown immediately."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name(prefix).rstrip("-")},
        },
        "CertificateAuthorityType": ca_type,
        "UsageMode": _USAGE_MODE,
        "Tags": [{"Key": "sim2real", "Value": scenario}],
    }
    resp = None
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(**body)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    assert resp is not None, "CreateCertificateAuthority did not return after 6 attempts"
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _teardown_ca(ctx, ca_arn))
    return ca_arn


def _await_certificate(ctx, ca_arn, cert_arn, *, timeout_s):
    """GetCertificate, polling through RequestInProgressException until signing completes."""
    pca = ctx.client("acm-pca")

    def _probe():
        try:
            return pca.get_certificate(
                CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "RequestInProgressException":
                return None
            raise

    got = _poll_until(
        _probe, lambda v: bool(v and v.get("Certificate")),
        timeout_s=timeout_s, interval_s=2.0,
        description=f"GetCertificate returning a signed certificate for {cert_arn}",
    )
    return got["Certificate"], got.get("CertificateChain")


def _fetch_csr(ctx, ca_arn, *, timeout_s):
    """GetCertificateAuthorityCsr, polling through the creation-in-progress guard."""
    pca = ctx.client("acm-pca")

    def _probe():
        try:
            return pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn).get("Csr")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("RequestInProgressException", "InvalidStateException"):
                return None
            raise

    return _poll_until(
        _probe, lambda v: bool(v), timeout_s=timeout_s, interval_s=2.0,
        description="GetCertificateAuthorityCsr returning a CSR",
    )


def _new_key_and_csr(common_name, dns_name):
    """A locally generated RSA-2048 key and a PKCS#10 request for it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return key_pem, csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


class _TlsServer:
    """A loopback TLS listener presenting a specific certificate chain."""

    def __init__(self, chain_path, key_path):
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(certfile=chain_path, keyfile=key_path)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._sock.settimeout(1.0)
        self.port = self._sock.getsockname()[1]
        self.handshake_errors: list[str] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with self._ctx.wrap_socket(raw, server_side=True) as tls:
                    payload = tls.recv(1)
                    if payload:
                        tls.sendall(payload)
            except (ssl.SSLError, OSError) as exc:
                self.handshake_errors.append(repr(exc))
                try:
                    raw.close()
                except OSError:
                    pass

    def close(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=10)


def _client_context(ca_pem_path):
    """A TLS client whose ONLY trust anchor is the file at ca_pem_path, hostname check on."""
    cli = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cli.verify_mode = ssl.CERT_REQUIRED
    cli.check_hostname = True
    cli.load_verify_locations(cafile=ca_pem_path)
    return cli


def _handshake_echo(port, client_ctx, server_hostname):
    """Complete a handshake and round-trip one application byte. Returns (peercert, echo)."""
    with socket.create_connection(("127.0.0.1", port), timeout=20) as raw:
        with client_ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
            peer = tls.getpeercert()
            tls.sendall(b"x")
            return peer, tls.recv(1)


def _handshake_error(port, client_ctx, server_hostname, *, what):
    """Attempt a handshake expected to be REFUSED; return the exception, never a falsy value."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=20) as raw:
            with client_ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
                tls.sendall(b"x")
                echoed = tls.recv(1)
    except ssl.SSLError as exc:
        return exc
    raise AssertionError(
        f"{what}: the handshake was EXPECTED to be refused but it COMPLETED and echoed "
        f"{echoed!r}"
    )


def _write(path, *pems):
    with open(path, "w", encoding="ascii") as fh:
        for pem in pems:
            if pem:
                fh.write(pem if pem.endswith("\n") else pem + "\n")


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A leaf signed by a subordinate CA (itself signed by the root) validates leaf -> sub -> root
    with only the root trusted, using CertificateChain; withholding the intermediate fails TLS.

    Reference: https://docs.aws.amazon.com/privateca/latest/userguide/ca-hierarchy.html
    """
    _require_local_crypto()

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import padding

    pca = ctx.client("acm-pca")
    timeout_s = 240
    scenario = "acm-pca-subordinate-chain"

    # ---- the root, activated by signing its own CSR ----
    root_arn = _create_ca(ctx, scenario, "ROOT", "sim2real-behav-pca-root-")
    _poll_until(
        lambda: _describe(ctx, root_arn),
        lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0, description="root CA reaching PENDING_CERTIFICATE",
    )
    root_csr = _fetch_csr(ctx, root_arn, timeout_s=timeout_s)
    root_cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=root_arn,
        Csr=root_csr.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_TEMPLATE,
        Validity={"Value": 3, "Type": "YEARS"},
    )["CertificateArn"]
    root_pem, _ = _await_certificate(ctx, root_arn, root_cert_arn, timeout_s=timeout_s)
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=root_arn, Certificate=root_pem.encode("ascii")
    )
    _poll_until(
        lambda: _describe(ctx, root_arn), lambda c: c.get("Status") == "ACTIVE",
        timeout_s=timeout_s, interval_s=2.0, description="root CA reaching ACTIVE",
    )

    # ---- the subordinate, signed BY THE ROOT ----
    sub_arn = _create_ca(ctx, scenario, "SUBORDINATE", "sim2real-behav-pca-sub-")
    _poll_until(
        lambda: _describe(ctx, sub_arn),
        lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0,
        description="subordinate CA reaching PENDING_CERTIFICATE",
    )
    sub_csr = _fetch_csr(ctx, sub_arn, timeout_s=timeout_s)
    sub_cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=root_arn,
        Csr=sub_csr.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_SUBORDINATE_TEMPLATE,
        Validity={"Value": _SUB_CA_DAYS, "Type": "DAYS"},
    )["CertificateArn"]
    sub_pem, _ = _await_certificate(ctx, root_arn, sub_cert_arn, timeout_s=timeout_s)
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=sub_arn,
        Certificate=sub_pem.encode("ascii"),
        CertificateChain=root_pem.encode("ascii"),
    )
    sub_status = _poll_until(
        lambda: _describe(ctx, sub_arn), lambda c: c.get("Status") == "ACTIVE",
        timeout_s=timeout_s, interval_s=2.0, description="subordinate CA reaching ACTIVE",
    )["Status"]
    assert sub_status == "ACTIVE", f"the subordinate CA did not activate: {sub_status!r}"

    root_cert = x509.load_pem_x509_certificate(root_pem.encode("ascii"))
    sub_cert = x509.load_pem_x509_certificate(sub_pem.encode("ascii"))

    assert sub_cert.issuer == root_cert.subject, (
        f"the subordinate certificate's issuer {sub_cert.issuer.rfc4514_string()!r} is not the "
        f"root's subject {root_cert.subject.rfc4514_string()!r}"
    )
    bc = sub_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True and bc.path_length == 0, (
        f"the subordinate certificate's basicConstraints are ca={bc.ca!r} "
        f"path_length={bc.path_length!r}, but the SubordinateCACertificate_PathLen0/V1 template "
        f"must produce CA:TRUE pathlen:0"
    )
    # Verify the upper hop's signature independently of the service.
    root_cert.public_key().verify(
        sub_cert.signature, sub_cert.tbs_certificate_bytes,
        padding.PKCS1v15(), sub_cert.signature_hash_algorithm,
    )

    # ---- the leaf, signed BY THE SUBORDINATE ----
    leaf_key_pem, leaf_csr_pem = _new_key_and_csr("localhost", "localhost")
    leaf_arn = pca.issue_certificate(
        CertificateAuthorityArn=sub_arn,
        Csr=leaf_csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_END_ENTITY_TEMPLATE,
        Validity={"Value": _LEAF_DAYS, "Type": "DAYS"},
    )["CertificateArn"]
    leaf_pem, leaf_chain_pem = _await_certificate(ctx, sub_arn, leaf_arn, timeout_s=timeout_s)
    leaf = x509.load_pem_x509_certificate(leaf_pem.encode("ascii"))

    assert leaf.issuer == sub_cert.subject, (
        f"the leaf's issuer {leaf.issuer.rfc4514_string()!r} is not the subordinate CA's "
        f"subject {sub_cert.subject.rfc4514_string()!r}, so it was not signed one level down"
    )
    # Verify the lower hop's signature independently of the service.
    sub_cert.public_key().verify(
        leaf.signature, leaf.tbs_certificate_bytes,
        padding.PKCS1v15(), leaf.signature_hash_algorithm,
    )
    chain_blocks = (leaf_chain_pem or "").count(_PEM_BEGIN)
    assert chain_blocks == 2, (
        f"GetCertificate returned a CertificateChain with {chain_blocks} PEM blocks, expected "
        f"the subordinate and the root. Chain was {(leaf_chain_pem or '')[:200]!r}"
    )
    chain_subjects = [
        x509.load_pem_x509_certificate(
            (_PEM_BEGIN + part).encode("ascii")
        ).subject.rfc4514_string()
        for part in (leaf_chain_pem or "").split(_PEM_BEGIN)[1:]
    ]
    assert chain_subjects == [sub_cert.subject.rfc4514_string(),
                              root_cert.subject.rfc4514_string()], (
        f"the returned chain is {chain_subjects!r}, expected the subordinate then the root"
    )

    # ---- OpenSSL builds the two-hop path, with the ROOT as its only anchor ----
    workdir = tempfile.mkdtemp(prefix="sim2real-acmpca-sub-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    _write(f"{workdir}/full-chain.pem", leaf_pem, leaf_chain_pem)
    _write(f"{workdir}/leaf-only.pem", leaf_pem)
    _write(f"{workdir}/key.pem", leaf_key_pem)
    _write(f"{workdir}/root.pem", root_pem)

    client = _client_context(f"{workdir}/root.pem")

    full = _TlsServer(f"{workdir}/full-chain.pem", f"{workdir}/key.pem")
    ctx.on_cleanup(full.close)
    peer, echoed = _handshake_echo(full.port, client, "localhost")
    assert echoed == b"x", (
        f"the two-level chain failed to carry a TLS session: the application byte was "
        f"{echoed!r}. Server-side handshake errors: {full.handshake_errors!r}"
    )
    assert peer and ("DNS", "localhost") in peer.get("subjectAltName", ()), (
        f"the validated peer certificate carries subjectAltName "
        f"{(peer or {}).get('subjectAltName')!r}, not the SAN the CSR requested"
    )

    # ---- control: withhold ACM-PCA's intermediate and the same client cannot build a path ----
    bare = _TlsServer(f"{workdir}/leaf-only.pem", f"{workdir}/key.pem")
    ctx.on_cleanup(bare.close)
    bare_exc = _handshake_error(
        bare.port, client, "localhost",
        what="a subordinate-issued leaf served WITHOUT the intermediate",
    )
    assert isinstance(bare_exc, ssl.SSLCertVerificationError), (
        f"serving the leaf without ACM-PCA's intermediate raised {type(bare_exc).__name__}: "
        f"{bare_exc!r}, expected an SSLCertVerificationError"
    )
    assert "unable to get local issuer certificate" in (bare_exc.verify_message or "").lower(), (
        f"the intermediate-withheld handshake failed with verify_message "
        f"{bare_exc.verify_message!r}; only a missing-issuer failure shows that the chain "
        f"ACM-PCA returned is what made the successful handshake possible"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
