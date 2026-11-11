"""issue-certificate-not-ready-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "issue-certificate-not-ready-fails"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']

_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _require_cryptography():
    """Decided before any create: this check's restore leg needs a real CSR and there is
    no oracle for that without the 'cryptography' package -- fail before billing starts."""
    import cryptography  # noqa: F401


def _generate_csr(common_name):
    """A locally generated RSA-2048 key and a PKCS#10 request for it, as PEM bytes."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Ordered, retrying teardown that ends at an OBSERVED Status == "DELETED".

    This check activates its CA, so a fire-and-forget delete is not enough: DeleteCertificateAuthority refuses an ACTIVE CA,
    and the meter keeps running (privateca bills every status except DELETED/FAILED) until
    DELETED is actually observed, not merely requested.
    """
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + 300
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = _describe(ctx, ca_arn).get("Status")
        except ClientError:
            return
        if last_status == "DELETED":
            return
        if last_status == "CREATING":
            time.sleep(3)
            continue
        if last_status == "ACTIVE":
            try:
                pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
            except ClientError:
                pass
            time.sleep(2)
            continue
        try:
            pca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
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
        f"Status=DELETED within 300s (last observed {last_status!r})."
    )


def _create_ca(ctx, **overrides):
    """Create a cheap ROOT CA (SHORT_LIVED_CERTIFICATE usage mode) and register its
    teardown. Retries on throttling since CreateCertificateAuthority has a low
    request-rate limit."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": "SHORT_LIVED_CERTIFICATE",
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    body.update(overrides)
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(**body)
            break
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "response", {}).get("Error", {}).get("Code")
            if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _teardown_ca(ctx, ca_arn))
    return ca_arn


def _wait_for_csr(ctx, ca_arn, timeout_s=120):
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("RequestInProgressException", "InvalidStateException"):
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"CSR for {ca_arn} was never ready within {timeout_s}s")


def _wait_for_certificate(ctx, ca_arn, cert_arn, timeout_s=120):
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return pca.get_certificate(
                CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn
            )["Certificate"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "RequestInProgressException":
                raise
        time.sleep(2)
    raise AssertionError(f"certificate {cert_arn} was never ready within {timeout_s}s")


def _wait_for_status(ctx, ca_arn, target, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe(ctx, ca_arn).get("Status")
        if last == target:
            return
        time.sleep(2)
    raise AssertionError(f"CA {ca_arn} never reached {target!r}, last saw {last!r}")


def _activate_root_ca(ctx, ca_arn):
    """Drive a PENDING_CERTIFICATE root CA to ACTIVE by having ACM-PCA sign its own CSR --
    the documented root-CA installation sequence: GetCertificateAuthorityCsr ->
    IssueCertificate(RootCACertificate/V1) against the CA's own arn -> GetCertificate ->
    ImportCertificateAuthorityCertificate."""
    pca = ctx.client("acm-pca")
    csr_pem = _wait_for_csr(ctx, ca_arn)
    root_cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_TEMPLATE,
        Validity={"Value": 3, "Type": "YEARS"},
    )["CertificateArn"]
    cert_pem = _wait_for_certificate(ctx, ca_arn, root_cert_arn)
    pca.import_certificate_authority_certificate(CertificateAuthorityArn=ca_arn, Certificate=cert_pem)
    _wait_for_status(ctx, ca_arn, "ACTIVE")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """IssueCertificate on a CA that is not yet ACTIVE is refused with InvalidStateException, and the
    identical call with the same CSR succeeds once the CA is activated, so readiness gated it."""
    _require_cryptography()
    pca = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    csr = _generate_csr(ctx.unique_name("sim2real-behav-pca-leaf-")[:64])
    call = dict(
        CertificateAuthorityArn=arn,
        Csr=csr,
        SigningAlgorithm="SHA256WITHRSA",
        Validity={"Value": 7, "Type": "DAYS"},
    )

    # Grade the CA's resting PENDING_CERTIFICATE state, not the transient CREATING window.
    _wait_for_status(ctx, arn, "PENDING_CERTIFICATE")
    refusal = _err(lambda: pca.issue_certificate(**call))
    assert refusal == (
        "InvalidStateException",
        "The certificate authority is not in a valid state for issuing certificates",
    ), refusal

    _activate_root_ca(ctx, arn)

    cert_arn = pca.issue_certificate(**call)["CertificateArn"]
    cert_pem = _wait_for_certificate(ctx, arn, cert_arn)
    assert "BEGIN CERTIFICATE" in cert_pem, (
        f"the identical IssueCertificate call succeeded once the CA was ACTIVE but "
        f"GetCertificate did not return a certificate PEM: {cert_pem[:80]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
