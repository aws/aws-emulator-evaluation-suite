"""root-ca-activation-then-tls-handshake-with-issued-leaf."""
from __future__ import annotations

import shutil
import socket
import ssl
import tempfile
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "root-ca-activation-then-tls-handshake-with-issued-leaf"
GROUP = 'data-plane'
SERVICES = ['acm-pca']

# DeleteCertificateAuthority models PermanentDeletionTimeInDays with range 7..30; 7 is the
# shortest soft-delete window the service allows. A CA in DELETED status is NOT billed
# ("For all status values except DELETED and FAILED, you are billed for the CA." --
# privateca/latest/userguide/PcaUpdateStatus.html), so reaching DELETED is the whole
# cost-control objective of the teardown below.
_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
# A short-lived-certificate-mode CA costs $50/CA/month rather than the $400 a general-purpose
# CA costs, and issues certificates of at most 7 days -- which is all a loopback handshake
# needs. Both figures are pro-rated (aws.amazon.com/private-ca/pricing).
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"
_LEAF_DAYS = 7


# ===== CA lifecycle helpers (self-contained) =====
# _create_ca tags the CA (its identifier is a server-minted UUID), and _teardown_ca polls until
# it observes Status == "DELETED", because that transition is what stops the meter.


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
    """Decided BEFORE any create: an absent parser cannot be discovered after billing starts.

    This check's grader is a local X.509 parse plus an OpenSSL handshake, neither of which the
    service under test can influence. Without the parser there is no oracle at all, so the
    honest outcome is an environment skip -- taken here, ahead of the CA create, rather than
    after it (host-capabilities.md: "put every fully-decidable gate ahead of every create").
    """
    from cryptography import x509  # noqa: F401


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Ordered, retrying, LOUD teardown that ends at an OBSERVED Status == "DELETED".

    DeleteCertificateAuthority accepts only CREATING, PENDING_CERTIFICATE, DISABLED or FAILED,
    so an ACTIVE CA must be DISABLED first, and a delete issued while the CA is still settling
    is refused with InvalidStateException. A cleanup that fires one delete and swallows the
    exception therefore leaks a metered private CA.
    Issuing the delete is also not enough on its own: the meter stops on the DELETED status,
    not on the API call, so this polls for that status and raises if it never arrives.
    """
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + 420
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = _describe(ctx, ca_arn).get("Status")
        except ClientError:
            return  # not addressable any more; nothing left to bill
        if last_status == "DELETED":
            return
        if last_status == "CREATING":
            time.sleep(3)
            continue
        if last_status == "ACTIVE":
            try:
                pca.update_certificate_authority(
                    CertificateAuthorityArn=ca_arn, Status="DISABLED"
                )
            except ClientError:
                pass
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
                time.sleep(3)
                continue
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(
        f"LEAKED BILLABLE RESOURCE: certificate authority {ca_arn} never reached "
        f"Status=DELETED within 420s (last observed {last_status!r}). It is STILL BILLING. "
        f"Delete it manually: UpdateCertificateAuthority(Status='DISABLED') then "
        f"DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
    )


def _create_ca(ctx, scenario, **overrides):
    """Create a CA and register its teardown AT CREATION TIME, before anything can assert.

    Tagged because a CA's only handle is a server-minted UUID and it carries no name, so the
    tag is what makes a stranded CA discoverable after the run.
    """
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": _USAGE_MODE,
        "Tags": [{"Key": "sim2real", "Value": scenario}],
    }
    body.update(overrides)
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


def _await_certificate(ctx, ca_arn, cert_arn, *, timeout_s):
    """GetCertificate, polling through RequestInProgressException until signing completes.

    Returns (certificate_pem, certificate_chain_pem_or_None). The RequestInProgressException
    arm is the observable condition that signing is asynchronous -- there is no sleep here
    standing in for it.
    """
    pca = ctx.client("acm-pca")

    def _probe():
        try:
            return pca.get_certificate(
                CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "RequestInProgressException":
                return None
            raise

    got = _poll_until(
        _probe, lambda v: bool(v and v.get("Certificate")),
        timeout_s=timeout_s, interval_s=2.0,
        description=f"GetCertificate returning a signed certificate for {cert_arn}",
    )
    return got["Certificate"], got.get("CertificateChain")


def _activate_root_ca(ctx, ca_arn, *, timeout_s):
    """Drive a PENDING_CERTIFICATE root CA to ACTIVE by having ACM-PCA sign its own CSR.

    This is the documented root-CA installation sequence (privateca userguide, "Install a root
    CA certificate"): GetCertificateAuthorityCsr -> IssueCertificate with the
    RootCACertificate/V1 template against the CA's OWN arn -> GetCertificate ->
    ImportCertificateAuthorityCertificate. Returns the CA certificate PEM.
    """
    pca = ctx.client("acm-pca")
    _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching PENDING_CERTIFICATE",
    )
    csr_pem = _fetch_csr(ctx, ca_arn, timeout_s=timeout_s)
    root_cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_TEMPLATE,
        Validity={"Value": 3, "Type": "YEARS"},
    )["CertificateArn"]
    ca_cert_pem, _ = _await_certificate(ctx, ca_arn, root_cert_arn, timeout_s=timeout_s)
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=ca_cert_pem.encode("ascii")
    )
    _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "ACTIVE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching ACTIVE after importing its own signed certificate",
    )
    return ca_cert_pem


def _new_key_and_csr(common_name, dns_name):
    """A locally generated RSA-2048 key and a PKCS#10 request for it.

    The key never leaves this process, which is what makes the issued leaf's public key a
    falsifiable claim: ACM-PCA can only produce a certificate carrying it by signing THIS csr.
    """
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
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return key, key_pem, csr_pem


def _self_signed_decoy_ca(common_name):
    """A locally generated CA the leaf does NOT chain to, used as a falsifiability control."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


class _TlsServer:
    """A loopback TLS listener presenting a specific chain. The CLIENT is the grader."""

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


def _handshake_error(port, client_ctx, server_hostname):
    """Attempt a handshake expected to be REFUSED; return the exception, never a falsy value."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=20) as raw:
            with client_ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
                tls.sendall(b"x")
                echoed = tls.recv(1)
    except ssl.SSLError as exc:
        return exc
    raise AssertionError(
        f"the handshake was EXPECTED to be refused but it COMPLETED and echoed {echoed!r}; "
        f"the client's trust anchor was not load-bearing, so nothing this check asserts about "
        f"chain validation is falsifiable"
    )


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A leaf ACM-PCA issues from an ACTIVE root CA carries the locally generated CSR key, its
    signature verifies under the CA certificate, and OpenSSL completes a TLS handshake with it for
    a client anchored only on that CA, while a client anchored on a decoy CA refuses it."""
    _require_local_crypto()

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    pca = ctx.client("acm-pca")
    timeout_s = 240
    scenario = "acm-pca-root-activation-tls-handshake"

    ca_arn = _create_ca(ctx, scenario)
    ca_cert_pem = _activate_root_ca(ctx, ca_arn, timeout_s=timeout_s)

    ca_status = _describe(ctx, ca_arn)["Status"]
    assert ca_status == "ACTIVE", (
        f"CA never activated after importing its own ACM-PCA-signed certificate: "
        f"{ca_status!r}"
    )

    # ---- the service does its work: sign a CSR whose key we hold ----
    leaf_key, leaf_key_pem, leaf_csr_pem = _new_key_and_csr("localhost", "localhost")
    leaf_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=leaf_csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_END_ENTITY_TEMPLATE,
        Validity={"Value": _LEAF_DAYS, "Type": "DAYS"},
    )["CertificateArn"]
    leaf_pem, leaf_chain_pem = _await_certificate(ctx, ca_arn, leaf_arn, timeout_s=timeout_s)

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("ascii"))
    leaf = x509.load_pem_x509_certificate(leaf_pem.encode("ascii"))

    assert leaf.issuer == ca_cert.subject, (
        f"the issued leaf's issuer {leaf.issuer.rfc4514_string()!r} is not the CA certificate's "
        f"subject {ca_cert.subject.rfc4514_string()!r}, so ACM-PCA did not sign with the CA "
        f"identity it activated"
    )

    want_spki = leaf_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    got_spki = leaf.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert got_spki == want_spki, (
        "the issued leaf does not carry the public key of the CSR that was submitted: the "
        f"certificate's SubjectPublicKeyInfo is {got_spki[:24].hex()}... but the locally "
        f"generated key's is {want_spki[:24].hex()}... -- the certificate was not produced by "
        "signing this request"
    )

    # An independent cryptographic oracle: the CA's public key must verify the leaf's
    # signature over its own tbsCertificate bytes. Nothing the service returns can make a
    # forged signature pass this.
    ca_cert.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        padding.PKCS1v15(),
        leaf.signature_hash_algorithm,
    )
    assert isinstance(leaf.signature_hash_algorithm, hashes.SHA256), (
        f"SigningAlgorithm=SHA256WITHRSA was requested but the leaf is signed with "
        f"{type(leaf.signature_hash_algorithm).__name__}"
    )

    leaf_sans = leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)
    assert leaf_sans == ["localhost"], (
        f"the issued leaf carries subjectAltName DNS entries {leaf_sans!r}, but the CSR "
        f"requested exactly ['localhost']"
    )

    # ---- OpenSSL grades the result ----
    workdir = tempfile.mkdtemp(prefix="sim2real-acmpca-tls-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    chain_path = f"{workdir}/leaf-chain.pem"
    key_path = f"{workdir}/leaf-key.pem"
    ca_path = f"{workdir}/ca.pem"
    decoy_path = f"{workdir}/decoy-ca.pem"
    with open(chain_path, "w", encoding="ascii") as fh:
        fh.write(leaf_pem if leaf_pem.endswith("\n") else leaf_pem + "\n")
        if leaf_chain_pem:
            fh.write(leaf_chain_pem if leaf_chain_pem.endswith("\n") else leaf_chain_pem + "\n")
    with open(key_path, "w", encoding="ascii") as fh:
        fh.write(leaf_key_pem)
    with open(ca_path, "w", encoding="ascii") as fh:
        fh.write(ca_cert_pem if ca_cert_pem.endswith("\n") else ca_cert_pem + "\n")
    with open(decoy_path, "w", encoding="ascii") as fh:
        fh.write(_self_signed_decoy_ca("sim2real-decoy-not-the-acm-pca-root"))

    server = _TlsServer(chain_path, key_path)
    ctx.on_cleanup(server.close)

    peer, echoed = _handshake_echo(server.port, _client_context(ca_path), "localhost")

    assert peer, (
        f"the TLS handshake completed but the client saw no peer certificate: {peer!r} -- "
        f"verification cannot have happened"
    )
    assert ("DNS", "localhost") in peer.get("subjectAltName", ()), (
        f"the peer certificate OpenSSL validated carries subjectAltName "
        f"{peer.get('subjectAltName')!r}, which does not contain the SAN the CSR requested"
    )
    assert echoed == b"x", (
        f"a TLS session was established with the ACM-PCA-issued leaf but the application byte "
        f"did not round-trip: {echoed!r}"
    )

    decoy_exc = _handshake_error(server.port, _client_context(decoy_path), "localhost")
    assert isinstance(decoy_exc, ssl.SSLCertVerificationError), (
        f"a client anchored on an unrelated locally self-signed CA raised "
        f"{type(decoy_exc).__name__}: {decoy_exc!r}, expected an SSLCertVerificationError -- "
        f"without this the successful handshake above does not prove the ACM-PCA chain was "
        f"what OpenSSL accepted"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
