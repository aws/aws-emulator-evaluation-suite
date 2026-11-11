"""restore-certificate-authority-unknown-ca-not-found."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "restore-certificate-authority-unknown-ca-not-found"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreCertificateAuthority on a well-formed but nonexistent CA ARN raises
    ResourceNotFoundException and leaves the real deleted CA untouched, which then restores with its
    own ARN."""
    pca = ctx.client("acm-pca")
    arn = _create_minimal_ca(ctx)
    _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE", "FAILED"}, timeout_s=90)

    pca.delete_certificate_authority(CertificateAuthorityArn=arn)
    _wait_for_status(ctx, arn, {"DELETED"}, timeout_s=60)

    # Well-formed but nonexistent: keep the ARN structure, swap in a fresh
    # random resource id that was never issued.
    fake_arn = arn.rsplit("/", 1)[0] + "/" + str(uuid.uuid4())
    code, message = _error(lambda: pca.restore_certificate_authority(CertificateAuthorityArn=fake_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Could not find specified CA", f"unexpected ResourceNotFoundException message: {message!r}"

    # Effect absent: the real CA is still DELETED, not restored.
    status = pca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
    assert status == "DELETED", f"expected CA to remain DELETED, got {status}"

    # Positive control: the real ARN restores successfully. A ROOT CA that never had a
    # certificate installed returns to PENDING_CERTIFICATE, not ACTIVE.
    pca.restore_certificate_authority(CertificateAuthorityArn=arn)
    restored_status = _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE"}, timeout_s=60)
    assert restored_status == "PENDING_CERTIFICATE", f"expected restore to reach PENDING_CERTIFICATE, got {restored_status}"


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
