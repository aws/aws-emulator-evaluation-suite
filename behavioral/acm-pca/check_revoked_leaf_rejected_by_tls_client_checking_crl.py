"""revoked-leaf-rejected-by-tls-client-checking-crl."""
from __future__ import annotations

import json
import shutil
import socket
import ssl
import tempfile
import threading
import time

from botocore.exceptions import ClientError
from fidelity_tests_runner import RequiredToolMissing

from behavioral_harness import tags

CHECK = "revoked-leaf-rejected-by-tls-client-checking-crl"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']

_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"
_LEAF_DAYS = 7
_REASON = "KEY_COMPROMISE"
_CRL_PREFIX = "crl/"
# ACM-PCA publishes the CRL asynchronously (documented as within 30 minutes; observed ~15
# minutes after RevokeCertificate), and no CRL object exists before then.
_CRL_POLL_TIMEOUT_S = 1500.0
_CRL_POLL_INTERVAL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=180, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _require_local_crypto():
    """Fail before any billable create if the cryptography package is missing."""
    try:
        from cryptography import x509  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise RequiredToolMissing(["cryptography"]) from exc


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Disable then delete the CA, polling until Status == "DELETED", where billing stops."""
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
            time.sleep(3)
            continue
        if last_status == "ACTIVE":
            try:
                pca.update_certificate_authority(
                    CertificateAuthorityArn=ca_arn, Status="DISABLED"
                )
            except ClientError as err:
                if err.response["Error"]["Code"] != "ResourceNotFoundException":
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


def _crl_bucket(ctx, scenario):
    """An S3 bucket ACM-PCA may publish CRLs into.

    The CA uses BUCKET_OWNER_FULL_CONTROL since Block Public Access refuses a public-read ACL.
    """
    s3 = ctx.client("s3")
    acct = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-pca-crl-").lower().rstrip("-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )

    def _empty_and_delete():
        try:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                        for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                if objs:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete)
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": scenario}]})
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AcmPcaCrlWrite",
            "Effect": "Allow",
            "Principal": {"Service": "acm-pca.amazonaws.com"},
            "Action": ["s3:PutObject", "s3:PutObjectAcl", "s3:GetBucketAcl",
                       "s3:GetBucketLocation"],
            "Resource": [f"arn:aws:s3:::{bucket}/*", f"arn:aws:s3:::{bucket}"],
            "Condition": {
                "StringEquals": {"aws:SourceAccount": acct},
                "ArnLike": {"aws:SourceArn":
                            f"arn:aws:acm-pca:{ctx.region}:{acct}:certificate-authority/*"},
            },
        }],
    }))
    return bucket


def _create_ca_with_crl(ctx, scenario, bucket):
    """Create a CRL-publishing root CA and register its teardown."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-crl-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": _USAGE_MODE,
        "RevocationConfiguration": {
            "CrlConfiguration": {
                "Enabled": True,
                "ExpirationInDays": 1,
                "S3BucketName": bucket,
                "S3ObjectAcl": "BUCKET_OWNER_FULL_CONTROL",
            },
        },
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
        ctx, _probe, lambda v: bool(v and v.get("Certificate")),
        timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0,
        description=f"GetCertificate returning a signed certificate for {cert_arn}",
    )
    return got["Certificate"], got.get("CertificateChain")


def _activate_root_ca(ctx, ca_arn, *, timeout_s):
    """Drive a PENDING_CERTIFICATE root CA to ACTIVE by having ACM-PCA sign its own CSR."""
    pca = ctx.client("acm-pca")
    _poll_until(
        ctx, lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0,
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
        ctx, _csr_probe, lambda v: bool(v), timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0,
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
        ctx, lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "ACTIVE",
        timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0,
        description="CA reaching ACTIVE after importing its own signed certificate",
    )
    return ca_cert_pem


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


def _load_crl_listing(ctx, bucket):
    """Every object key under the CRL prefix, paginated."""
    s3 = ctx.client("s3")
    keys = []
    token = None
    while True:
        kw = {"Bucket": bucket, "Prefix": _CRL_PREFIX}
        if token:
            kw["ContinuationToken"] = token
        page = s3.list_objects_v2(**kw)
        keys.extend(o["Key"] for o in page.get("Contents", []))
        token = page.get("NextContinuationToken")
        if not token:
            break
    return keys


def _await_crl_listing_serial(ctx, bucket, serial):
    """Poll the CRL prefix until a parseable CRL that lists `serial` appears; return it."""
    from cryptography import x509

    def _probe():
        for key in _load_crl_listing(ctx, bucket):
            body = ctx.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read()
            try:
                crl = x509.load_der_x509_crl(body)
            except ValueError:
                try:
                    crl = x509.load_pem_x509_crl(body)
                except ValueError:
                    continue
            if crl.get_revoked_certificate_by_serial_number(serial) is not None:
                return crl
        return None

    return _poll_until(
        ctx, _probe, lambda v: v is not None,
        timeout_s=_budget_s(ctx, _CRL_POLL_TIMEOUT_S), interval_s=_CRL_POLL_INTERVAL_S,
        description=(
            f"ACM-PCA publishing a CRL under s3://{bucket}/{_CRL_PREFIX} that lists the revoked "
            f"serial {serial:x}"
        ),
    )


class _TlsServer:
    """A loopback TLS listener presenting a specific chain; the client makes the trust decision."""

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


def _client_context(anchor_path, *, check_crl):
    """A TLS client anchored ONLY on anchor_path, optionally enforcing the CRL found there.

    OpenSSL reads PEM CRLs out of the same CAfile as the certificates, which is why the caller
    concatenates the CA certificate and the converted CRL into one file.
    """
    cli = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cli.verify_mode = ssl.CERT_REQUIRED
    cli.check_hostname = True
    if check_crl:
        cli.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    cli.load_verify_locations(cafile=anchor_path)
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


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Revoking one leaf makes ACM-PCA publish a CA-signed CRL listing that serial with its reason,
    and a CRL-enforcing TLS client refuses that leaf as revoked while still accepting an unrevoked
    leaf from the same CA.

    Reference: https://docs.aws.amazon.com/privateca/latest/userguide/crl-planning.html
    """
    _require_local_crypto()

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    pca = ctx.client("acm-pca")
    timeout_s = 240
    scenario = "acm-pca-crl-revocation-tls"

    bucket = _crl_bucket(ctx, scenario)
    ca_arn = _create_ca_with_crl(ctx, scenario, bucket)
    ca_cert_pem = _activate_root_ca(ctx, ca_arn, timeout_s=timeout_s)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("ascii"))

    revocation = _describe(ctx, ca_arn).get("RevocationConfiguration", {})
    assert revocation.get("CrlConfiguration", {}).get("Enabled") is True, (
        f"the CA does not report CRL publication as enabled, so no CRL can be expected: "
        f"{revocation!r}"
    )

    leaves = {}
    for label in ("revoked", "control"):
        key_pem, csr_pem = _new_key_and_csr("localhost", "localhost")
        arn = pca.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=csr_pem.encode("ascii"),
            SigningAlgorithm="SHA256WITHRSA",
            TemplateArn=_END_ENTITY_TEMPLATE,
            Validity={"Value": _LEAF_DAYS, "Type": "DAYS"},
        )["CertificateArn"]
        pem, chain = _await_certificate(ctx, ca_arn, arn, timeout_s=timeout_s)
        leaves[label] = {
            "key_pem": key_pem, "pem": pem, "chain": chain,
            "serial": x509.load_pem_x509_certificate(pem.encode("ascii")).serial_number,
        }
    assert leaves["revoked"]["serial"] != leaves["control"]["serial"], (
        f"both leaves share serial {leaves['revoked']['serial']!r}, so the control cannot "
        f"distinguish a targeted revocation from a blanket one"
    )

    workdir = tempfile.mkdtemp(prefix="sim2real-acmpca-crl-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    _write(f"{workdir}/ca.pem", ca_cert_pem)
    servers = {}
    for label, leaf in leaves.items():
        _write(f"{workdir}/{label}-chain.pem", leaf["pem"], leaf["chain"])
        _write(f"{workdir}/{label}-key.pem", leaf["key_pem"])
        servers[label] = _TlsServer(f"{workdir}/{label}-chain.pem",
                                    f"{workdir}/{label}-key.pem")
        ctx.on_cleanup(servers[label].close)

    # The control handshake succeeds before any revocation, so a later refusal is attributable.
    _, pre_echo = _handshake_echo(
        servers["control"].port, _client_context(f"{workdir}/ca.pem", check_crl=False),
        "localhost",
    )
    assert pre_echo == b"x", (
        f"the control leaf could not complete a handshake even before any revocation "
        f"(byte was {pre_echo!r}); every refusal below would be unattributable. Server-side "
        f"errors: {servers['control'].handshake_errors!r}"
    )

    # RevokeCertificate takes the serial as lowercase hex with no separators.
    pca.revoke_certificate(
        CertificateAuthorityArn=ca_arn,
        CertificateSerial=format(leaves["revoked"]["serial"], "x"),
        RevocationReason=_REASON,
    )

    crl = _await_crl_listing_serial(ctx, bucket, leaves["revoked"]["serial"])

    assert crl.issuer == ca_cert.subject, (
        f"the published CRL's issuer is {crl.issuer.rfc4514_string()!r}, not the CA "
        f"certificate's subject {ca_cert.subject.rfc4514_string()!r}"
    )
    assert crl.is_signature_valid(ca_cert.public_key()), (
        "the published CRL's signature does not verify under the CA certificate's public key; "
        "it is structurally a CRL but was not signed by this CA"
    )
    revoked_entry = crl.get_revoked_certificate_by_serial_number(leaves["revoked"]["serial"])
    assert revoked_entry is not None, (
        f"serial {leaves['revoked']['serial']:x} was revoked but is absent from the published "
        f"CRL, which lists {[f'{r.serial_number:x}' for r in crl]!r}"
    )
    reason = revoked_entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
    assert reason == x509.ReasonFlags.key_compromise, (
        f"the CRL records revocation reason {reason!r} for the revoked serial, but "
        f"RevokeCertificate was called with {_REASON!r}"
    )
    assert crl.get_revoked_certificate_by_serial_number(
        leaves["control"]["serial"]
    ) is None, (
        f"the CRL also lists the control serial {leaves['control']['serial']:x}, which was "
        f"never revoked; it lists {[f'{r.serial_number:x}' for r in crl]!r}"
    )

    # OpenSSL reads PEM CRLs from the CAfile, so the DER CRL is converted and appended.
    crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode("ascii")
    _write(f"{workdir}/ca-and-crl.pem", ca_cert_pem, crl_pem)
    crl_client = _client_context(f"{workdir}/ca-and-crl.pem", check_crl=True)

    revoked_exc = _handshake_error(
        servers["revoked"].port, crl_client, "localhost",
        what="a leaf listed in the CA's own CRL",
    )
    assert isinstance(revoked_exc, ssl.SSLCertVerificationError), (
        f"the handshake with the revoked leaf raised {type(revoked_exc).__name__}: "
        f"{revoked_exc!r}, expected an SSLCertVerificationError"
    )
    assert "revoked" in (revoked_exc.verify_message or "").lower(), (
        f"verification failed for the wrong reason: verify_message was "
        f"{revoked_exc.verify_message!r}. Only a revocation failure shows that the CRL's "
        f"CONTENT is what OpenSSL acted on -- an unfetchable or missing CRL fails here too, "
        f"with a different message"
    )

    peer, echoed = _handshake_echo(servers["control"].port, crl_client, "localhost")
    assert echoed == b"x", (
        f"positive control: the never-revoked leaf from the same CA, through the identical "
        f"CRL-enforcing client context, failed to round-trip a byte: {echoed!r}. Server-side "
        f"errors: {servers['control'].handshake_errors!r}"
    )
    peer_serial = int(peer.get("serialNumber", "0"), 16)
    assert peer_serial == leaves["control"]["serial"], (
        f"the control handshake presented serial {peer_serial:x}, expected "
        f"{leaves['control']['serial']:x}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
