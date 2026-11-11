"""ca-certificate-key-usage-forbids-server-auth-for-tls."""
from __future__ import annotations

import shutil
import socket
import ssl
import tempfile
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ca-certificate-key-usage-forbids-server-auth-for-tls"
GROUP = 'data-plane'
SERVICES = ['acm-pca']

_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_CODE_SIGNING_TEMPLATE = "arn:aws:acm-pca:::template/CodeSigningCertificate/V1"
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"
_LEAF_DAYS = 7
# id-kp-serverAuth / id-kp-clientAuth / id-kp-codeSigning, spelled as OIDs so the assertions do
# not depend on any library's short-name table.
_OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
_OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"


# ===== CA lifecycle helpers (self-contained) =====
# The teardown polls until it observes Status == "DELETED" (the transition that stops the
# meter); _create_ca tags the CA, whose only handle is a server-minted UUID.


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
    """Decided BEFORE any create: an absent parser cannot be discovered after billing starts."""
    from cryptography import x509  # noqa: F401


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Ordered, retrying, LOUD teardown that ends at an OBSERVED Status == "DELETED".

    The meter stops on the DELETED status, not on the delete call, and ctx.on_cleanup swallows
    whatever this raises -- so it polls for that status rather than assuming the call took.
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
    """Create a CA and register its teardown AT CREATION TIME, before anything can assert."""
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


def _activate_root_ca(ctx, ca_arn, *, timeout_s):
    """Drive a PENDING_CERTIFICATE root CA to ACTIVE by having ACM-PCA sign its own CSR.

    The documented root-CA installation sequence (privateca userguide, "Install a root CA
    certificate"): GetCertificateAuthorityCsr -> IssueCertificate with the RootCACertificate/V1
    template against the CA's OWN arn -> GetCertificate -> ImportCertificateAuthorityCertificate.
    """
    pca = ctx.client("acm-pca")
    _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching PENDING_CERTIFICATE",
    )

    def _csr_probe():
        try:
            return pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn).get("Csr")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("RequestInProgressException", "InvalidStateException"):
                return None
            raise

    csr_pem = _poll_until(
        _csr_probe, lambda v: bool(v), timeout_s=timeout_s, interval_s=2.0,
        description="GetCertificateAuthorityCsr returning a CSR",
    )
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
    """ONE locally generated RSA-2048 key and ONE PKCS#10 request, shared by both templates.

    Both leaves below are signed over these identical bytes, so the ONLY difference between
    them is the TemplateArn -- which is what makes the extendedKeyUsage difference attributable
    to the template rather than to the request.
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
    return key_pem, csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


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
    """A TLS client whose ONLY trust anchor is the file at ca_pem_path, hostname check on.

    A stdlib TLS client also enforces the serverAuth PURPOSE during chain verification --
    measured on this host: a codeSigning-only leaf under a trusted CA fails with
    "unsuitable certificate purpose". So no `openssl verify -purpose` subprocess is needed.
    """
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


def _eku_oids(cert):
    from cryptography import x509

    try:
        ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return None
    return sorted(oid.dotted_string for oid in ext)


def _write(path, *pems):
    with open(path, "w", encoding="ascii") as fh:
        for pem in pems:
            if pem:
                fh.write(pem if pem.endswith("\n") else pem + "\n")


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """The TemplateArn decides the extendedKeyUsage in the signed leaf, and it governs use: a
    CodeSigningCertificate/V1 leaf is refused by OpenSSL as a TLS server certificate, while an
    EndEntityCertificate/V1 leaf over the identical CSR from the same CA completes the handshake."""
    _require_local_crypto()

    from cryptography import x509

    pca = ctx.client("acm-pca")
    timeout_s = 240
    scenario = "acm-pca-template-eku-tls-purpose"

    ca_arn = _create_ca(ctx, scenario)
    ca_cert_pem = _activate_root_ca(ctx, ca_arn, timeout_s=timeout_s)

    key_pem, csr_pem = _new_key_and_csr("localhost", "localhost")
    csr_bytes = csr_pem.encode("ascii")

    def _issue(template):
        arn = pca.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=csr_bytes,
            SigningAlgorithm="SHA256WITHRSA",
            TemplateArn=template,
            Validity={"Value": _LEAF_DAYS, "Type": "DAYS"},
        )["CertificateArn"]
        pem, chain = _await_certificate(ctx, ca_arn, arn, timeout_s=timeout_s)
        return pem, chain

    cs_pem, cs_chain = _issue(_CODE_SIGNING_TEMPLATE)
    srv_pem, srv_chain = _issue(_END_ENTITY_TEMPLATE)

    cs_cert = x509.load_pem_x509_certificate(cs_pem.encode("ascii"))
    srv_cert = x509.load_pem_x509_certificate(srv_pem.encode("ascii"))
    cs_eku = _eku_oids(cs_cert)
    srv_eku = _eku_oids(srv_cert)

    assert cs_eku is not None and _OID_CODE_SIGNING in cs_eku, (
        f"the CodeSigningCertificate/V1 template produced extendedKeyUsage {cs_eku!r}, which "
        f"does not include codeSigning ({_OID_CODE_SIGNING})"
    )
    assert _OID_SERVER_AUTH not in cs_eku, (
        f"the CodeSigning template leaf carries serverAuth ({_OID_SERVER_AUTH}) in its "
        f"extendedKeyUsage {cs_eku!r}; a code-signing certificate that is also a valid TLS "
        f"server certificate is exactly the over-permissive outcome the template exists to "
        f"prevent"
    )
    assert srv_eku is not None and _OID_SERVER_AUTH in srv_eku, (
        f"the EndEntityCertificate/V1 template produced extendedKeyUsage {srv_eku!r}, which "
        f"does not include serverAuth ({_OID_SERVER_AUTH})"
    )
    # Excludes the confound: if the CodeSigning template dropped the requested SAN, the
    # handshake below would fail on a HOSTNAME mismatch and the purpose would never be tested.
    cs_sans = cs_cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)
    assert cs_sans == ["localhost"], (
        f"the CodeSigning leaf carries subjectAltName DNS entries {cs_sans!r} rather than the "
        f"['localhost'] the CSR requested, so a refused handshake below could not be "
        f"attributed to the certificate's purpose"
    )

    workdir = tempfile.mkdtemp(prefix="sim2real-acmpca-eku-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    _write(f"{workdir}/cs-chain.pem", cs_pem, cs_chain)
    _write(f"{workdir}/srv-chain.pem", srv_pem, srv_chain)
    _write(f"{workdir}/key.pem", key_pem)
    _write(f"{workdir}/ca.pem", ca_cert_pem)

    client = _client_context(f"{workdir}/ca.pem")

    cs_server = _TlsServer(f"{workdir}/cs-chain.pem", f"{workdir}/key.pem")
    ctx.on_cleanup(cs_server.close)
    cs_exc = _handshake_error(
        cs_server.port, client, "localhost",
        what="a codeSigning-only leaf presented as a TLS server certificate",
    )
    assert isinstance(cs_exc, ssl.SSLCertVerificationError), (
        f"a TLS handshake presenting the codeSigning-only leaf raised "
        f"{type(cs_exc).__name__}: {cs_exc!r}, expected an SSLCertVerificationError"
    )
    assert "unsuitable certificate purpose" in (cs_exc.verify_message or "").lower(), (
        f"the handshake was refused for the wrong reason: verify_message was "
        f"{cs_exc.verify_message!r}. Only a purpose failure shows that the template's "
        f"extendedKeyUsage is what OpenSSL acted on"
    )

    srv_server = _TlsServer(f"{workdir}/srv-chain.pem", f"{workdir}/key.pem")
    ctx.on_cleanup(srv_server.close)
    peer, echoed = _handshake_echo(srv_server.port, client, "localhost")
    assert echoed == b"x", (
        f"positive control: the EndEntity leaf from the same CA, over the same CSR and through "
        f"the identical client context, failed to round-trip a byte: {echoed!r}"
    )
    assert peer and ("DNS", "localhost") in peer.get("subjectAltName", ()), (
        f"positive control: the validated peer certificate carries subjectAltName "
        f"{(peer or {}).get('subjectAltName')!r}, not the SAN the CSR requested"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
