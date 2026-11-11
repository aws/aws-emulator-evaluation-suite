"""restore-certificate-authority-malformed-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "restore-certificate-authority-malformed-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreCertificateAuthority with a syntactically invalid CA ARN returns
    InvalidArnException, leaves the real (deleted) CA untouched, while restoring
    it with the correctly-formed ARN succeeds as a positive control."""
    pca = ctx.client("acm-pca")
    arn = _create_minimal_ca(ctx)
    _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE", "FAILED"}, timeout_s=90)

    pca.delete_certificate_authority(CertificateAuthorityArn=arn)
    _wait_for_status(ctx, arn, {"DELETED"}, timeout_s=60)

    # Malformed: strip the "/<resource-id>" suffix so the ARN no longer matches
    # the acm-pca certificate-authority ARN pattern.
    malformed_arn = arn.rsplit("/", 1)[0]
    code, message = _error(lambda: pca.restore_certificate_authority(CertificateAuthorityArn=malformed_arn))
    assert code == "InvalidArnException", f"expected InvalidArnException, got {code}"
    assert message == "Not a valid arn.", f"unexpected InvalidArnException message: {message!r}"

    # Effect absent: the real CA is still DELETED, not restored.
    status = pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
    assert status == "DELETED", f"expected CA to remain DELETED, got {status}"

    # Positive control: the well-formed ARN restores successfully. This CA never had a
    # certificate installed, so restore must return it to the exact pre-delete state
    # (PENDING_CERTIFICATE) -- not just "some status other than DELETED".
    pca.restore_certificate_authority(CertificateAuthorityArn=arn)
    restored_status = _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE"}, timeout_s=60)
    assert restored_status == "PENDING_CERTIFICATE", f"expected CA to restore to PENDING_CERTIFICATE, got {restored_status}"


def _error(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_minimal_ca(ctx) -> str:
    pca = ctx.client("acm-pca")
    resp = pca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, arn))
    return arn


def _safe_delete_ca(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    pca = ctx.client("acm-pca")
    try:
        pca.delete_certificate_authority(CertificateAuthorityArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_status(ctx, arn: str, target_statuses: set[str], timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if last_status in target_statuses:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"CA never reached one of {target_statuses}, last status was {last_status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
