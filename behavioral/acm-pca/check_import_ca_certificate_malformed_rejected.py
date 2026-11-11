"""import-ca-certificate-malformed-rejected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-ca-certificate-malformed-rejected"
GROUP = 'error-semantics'
SERVICES = ['acm-pca']

_MALFORMED_CERT_PEM = (
    b"-----BEGIN CERTIFICATE-----\n"
    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    b"QUJD\n"
    b"-----END CERTIFICATE-----\n"
)

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")

def _delete_ca(ctx, ca_arn):
    """An ACTIVE CA cannot be deleted, so disable it first (the check activates it)."""
    pca = ctx.client("acm-pca")
    try:
        status = _status(ctx, ca_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "DELETED":
        return
    if status == "ACTIVE":
        pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DISABLED", timeout_s=60.0)
    pca.delete_certificate_authority(
        CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
    )

def _create_ca(ctx, **overrides):
    """Create a ROOT CA and register its teardown. Retries on throttling since
    CreateCertificateAuthority has a low request-rate limit."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
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
    ctx.on_cleanup(lambda: _delete_ca(ctx, ca_arn))
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "PENDING_CERTIFICATE", timeout_s=60.0)
    return ca_arn


def _status(ctx, ca_arn):
    pca = ctx.client("acm-pca")
    return pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_for_csr(ctx, ca_arn, timeout_s=60.0):
    pca = ctx.client("acm-pca")

    def _get():
        try:
            return pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    return _poll_until(_get, lambda v: v is not None, timeout_s=timeout_s)


def _self_sign(ctx, ca_arn, csr):
    """Self-issue a root certificate for ca_arn's own CSR -- the standard AWS
    Private CA root-activation flow, used here as the positive control."""
    pca = ctx.client("acm-pca")
    cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 365, "Type": "DAYS"},
    )["CertificateArn"]

    def _get():
        try:
            return pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    return _poll_until(_get, lambda v: v is not None, timeout_s=60.0)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportCertificateAuthorityCertificate refuses a non-X.509 blob with ValidationException
    and leaves the CA in PENDING_CERTIFICATE; importing the CA's own self-signed
    certificate afterwards succeeds."""
    pca = ctx.client("acm-pca")
    arn = _create_ca(ctx)

    refusal = _err(
        lambda: pca.import_certificate_authority_certificate(
            CertificateAuthorityArn=arn, Certificate=_MALFORMED_CERT_PEM
        )
    )
    assert refusal == (
        "ValidationException",
        "1 validation error detected: Value at 'certificate' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: "
        r"-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9/+]{64}\r?\n)*[A-Za-z0-9/+]{1,64}={0,2}"
        r"\r?\n-----END CERTIFICATE-----(\r?\n)?.",
    ), refusal

    # effect absent: the malformed blob never advanced the CA out of PENDING_CERTIFICATE.
    assert _status(ctx, arn) == "PENDING_CERTIFICATE", _status(ctx, arn)

    # positive control: the CA's own matching self-signed certificate imports and activates it,
    # proving the rejection above was specific to the malformed bytes, not to import being blocked.
    csr = _wait_for_csr(ctx, arn)
    cert_pem = _self_sign(ctx, arn, csr)
    pca.import_certificate_authority_certificate(CertificateAuthorityArn=arn, Certificate=cert_pem)
    status = _poll_until(lambda: _status(ctx, arn), lambda s: s == "ACTIVE", timeout_s=60.0)
    assert status == "ACTIVE", status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
