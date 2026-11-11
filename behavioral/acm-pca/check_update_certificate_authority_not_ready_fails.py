"""update-certificate-authority-not-ready-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-certificate-authority-not-ready-fails"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']

_ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised. An
    unexpected SUCCESS raises, so an accepted call is reported as such rather than
    as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")

def _describe_status(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]["Status"]

def _wait_for_status(ctx, ca_arn, target_statuses, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe_status(ctx, ca_arn)
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"status never reached {target_statuses}, last saw {last!r}")

def _wait_for_certificate(ctx, ca_arn, cert_arn, timeout_s=90.0, interval_s=3.0):
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as exc:
            last_code = exc.response.get("Error", {}).get("Code")
            if last_code != "RequestInProgressException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"certificate never became available, last error: {last_code!r}")

def _activate_root_ca(ctx, ca_arn):
    """Self-install a root certificate so the CA transitions PENDING_CERTIFICATE ->
    ACTIVE, the only way a ROOT CA leaves its not-ready state."""
    pca = ctx.client("acm-pca")
    _wait_for_status(ctx, ca_arn, {"PENDING_CERTIFICATE"}, timeout_s=90)
    csr = pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
    cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_TEMPLATE_ARN,
        Validity={"Value": 365, "Type": "DAYS"},
    )["CertificateArn"]
    cert_pem = _wait_for_certificate(ctx, ca_arn, cert_arn)
    pca.import_certificate_authority_certificate(CertificateAuthorityArn=ca_arn, Certificate=cert_pem)
    _wait_for_status(ctx, ca_arn, {"ACTIVE"}, timeout_s=90)

def _delete_ca(ctx, ca_arn):
    pca = ctx.client("acm-pca")
    try:
        status = pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "ACTIVE":
        pca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        status = _wait_for_status(ctx, ca_arn, {"DISABLED"}, timeout_s=90)
    if status in ("DISABLED", "PENDING_CERTIFICATE", "CREATING", "EXPIRED", "FAILED"):
        pca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)

def _create_ca(ctx, **overrides):
    """Create a cheap ROOT CA (SHORT_LIVED_CERTIFICATE usage mode, never issues a
    leaf cert) and register its teardown. Retries on throttling since
    CreateCertificateAuthority has a low request-rate limit."""
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
    ctx.on_cleanup(lambda: _delete_ca(ctx, ca_arn))
    return ca_arn

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCertificateAuthority on a PENDING_CERTIFICATE CA fails with
    InvalidStateException and leaves it unchanged; the same call succeeds on an
    ACTIVE CA and on the same CA once its root certificate is installed."""
    pca = ctx.client("acm-pca")

    # Positive control: on an ACTIVE CA the same call really does succeed.
    control_arn = _create_ca(ctx)
    _activate_root_ca(ctx, control_arn)
    pca.update_certificate_authority(CertificateAuthorityArn=control_arn, Status="DISABLED")
    control_status = _describe_status(ctx, control_arn)
    assert control_status == "DISABLED", control_status

    # Break (naturally): a freshly created ROOT CA settles into PENDING_CERTIFICATE
    # (it briefly reports CREATING right after CreateCertificateAuthority).
    arn = _create_ca(ctx)
    status = _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE", "FAILED"}, timeout_s=90)
    assert status == "PENDING_CERTIFICATE", status

    code, message = _err(
        lambda: pca.update_certificate_authority(
            CertificateAuthorityArn=arn, Status="DISABLED"
        )
    )
    assert code == "InvalidStateException", code
    assert message == (
        "The certificate authority must be in the ACTIVE or DISABLED state to be updated"
    ), message

    # Effect absent: the rejected call did not move the CA out of PENDING_CERTIFICATE.
    status = _describe_status(ctx, arn)
    assert status == "PENDING_CERTIFICATE", status

    # Restore: activate this same CA, then the identical call now succeeds.
    _activate_root_ca(ctx, arn)
    pca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
    status = _describe_status(ctx, arn)
    assert status == "DISABLED", status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
