"""ca-delete-restore-reactivates-pending-state."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags


CHECK = "ca-delete-restore-reactivates-pending-state"
GROUP = "state-machine"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deleted then restored PENDING_CERTIFICATE CA returns to PENDING_CERTIFICATE, not ACTIVE."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))

    status = _poll_until(
        lambda: _status(ctx, ca_arn),
        lambda s: s in ("PENDING_CERTIFICATE", "FAILED"),
        timeout_s=60,
    )
    assert status == "PENDING_CERTIFICATE", f"CA did not reach PENDING_CERTIFICATE, got {status}"

    acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DELETED", timeout_s=60)

    acmpca.restore_certificate_authority(CertificateAuthorityArn=ca_arn)
    restored_status = _poll_until(lambda: _status(ctx, ca_arn), lambda s: s != "DELETED", timeout_s=60)

    assert restored_status == "PENDING_CERTIFICATE", (
        f"restored CA should return to its pre-delete PENDING_CERTIFICATE state, got {restored_status}"
    )
    assert restored_status != "ACTIVE", (
        f"restore must not reactivate the CA to ACTIVE, got {restored_status}"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
