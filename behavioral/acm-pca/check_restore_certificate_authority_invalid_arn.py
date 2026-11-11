"""restore-certificate-authority-invalid-arn."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "restore-certificate-authority-invalid-arn"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]

_ARN_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'certificateAuthorityArn' failed to satisfy constraint: "
    "Member must satisfy regular expression pattern: "
    "arn:[\\w+=/,.@-]+:acm-pca:[\\w+=/,.@-]*:[0-9]*:[\\w+=,.@-]+(/[\\w+=,.@-]+)*"
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreCertificateAuthority rejects a malformed CA ARN as an input-shape error,
    distinct from ResourceNotFoundException for a well-formed unknown ARN, while a
    real DELETED CA still restores (positive control)."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))

    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s in ("PENDING_CERTIFICATE", "FAILED"), timeout_s=60)
    acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DELETED", timeout_s=60)

    malformed_arn = "not-an-acm-pca-arn"
    code, message = _error(lambda: acmpca.restore_certificate_authority(CertificateAuthorityArn=malformed_arn))
    assert code == "ValidationException", code
    assert message == _ARN_PATTERN_MESSAGE, message

    # (b) effect absent: the real (unrelated) CA is untouched by the malformed call.
    status_after_reject = _status(ctx, ca_arn)
    assert status_after_reject == "DELETED", f"expected CA to remain DELETED, got {status_after_reject}"

    # (c) positive control: restoring the real, well-formed, existing CA ARN succeeds.
    acmpca.restore_certificate_authority(CertificateAuthorityArn=ca_arn)
    restored_status = _poll_until(lambda: _status(ctx, ca_arn), lambda s: s != "DELETED", timeout_s=60)
    assert restored_status == "PENDING_CERTIFICATE", f"expected PENDING_CERTIFICATE, got {restored_status}"


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _status(ctx, ca_arn: str) -> str:
    acmpca = ctx.client("acm-pca")
    return acmpca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]


def _create_root_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")[:64]},
        },
        Tags=[{"Key": "sim2real", "Value": "restore-certificate-authority-invalid-arn"}],
    )
    return resp["CertificateAuthorityArn"]


def _safe_delete_ca(ctx, ca_arn: str) -> None:
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    try:
        status = _status(ctx, ca_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "ACTIVE":
        acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
        _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DISABLED", timeout_s=60)
    if status != "DELETED":
        acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
