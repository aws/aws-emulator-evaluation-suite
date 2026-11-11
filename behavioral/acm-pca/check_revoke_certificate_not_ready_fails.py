"""revoke-certificate-not-ready-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revoke-certificate-not-ready-fails"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). A call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

def _wait_for_status(pca, ca_arn, target_statuses, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = pca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"CA {ca_arn} never reached {target_statuses}, last status={last!r}")

def _delete_ca(ctx, ca_arn):
    try:
        ctx.client("acm-pca").delete_certificate_authority(
            CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _create_ca(ctx, **overrides):
    """Create a cheap, never-activated ROOT CA (SHORT_LIVED_CERTIFICATE usage mode,
    never issues a cert) and register its teardown. Retries on throttling since
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
        "Tags": [{"Key": "sim2real", "Value": "revoke-certificate-not-ready-fails"}],
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
    """RevokeCertificate against a CA held in DELETED is rejected with InvalidStateException, and the
    rejected call leaves the CA's reported state unchanged."""
    pca = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    _wait_for_status(pca, arn, {"PENDING_CERTIFICATE"})
    pca.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)
    status_before = _wait_for_status(pca, arn, {"DELETED"})

    code, message = _err(
        lambda: pca.revoke_certificate(
            CertificateAuthorityArn=arn,
            CertificateSerial="0a:1b:2c:3d:4e:5f:60:71",
            RevocationReason="KEY_COMPROMISE",
        )
    )
    assert code == "InvalidStateException", f"expected InvalidStateException, got {code!r}"
    assert message == (
        f"The certificate authority {arn} is not in the correct state to have issued certificates."
    ), f"unexpected InvalidStateException message: {message!r}"

    status_after = pca.describe_certificate_authority(CertificateAuthorityArn=arn)[
        "CertificateAuthority"
    ]["Status"]
    assert status_after == status_before, (
        f"rejected RevokeCertificate changed CA status: {status_before!r} -> {status_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
