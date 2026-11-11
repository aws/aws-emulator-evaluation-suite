"""restore-certificate-authority-from-deleted-within-window."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-certificate-authority-from-deleted-within-window"
GROUP = "state-machine"
SERVICES = ["acm-pca"]

_KEY_ALGORITHM = "RSA_2048"
_SIGNING_ALGORITHM = "SHA256WITHRSA"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CA deleted while still PENDING_CERTIFICATE (with a 7-30 day restore window) can
    be restored via RestoreCertificateAuthority, transitioning status from DELETED back
    to its prior PENDING_CERTIFICATE status."""
    client = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, arn))

    status = _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE"}, timeout_s=90)
    assert status == "PENDING_CERTIFICATE", f"expected CA to reach PENDING_CERTIFICATE, got {status!r}"

    # Minimum allowed restoration window is 7 days; the window length itself is not
    # what we are testing -- we only need the CA to land in DELETED and be restorable.
    client.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)
    deleted_status = _wait_for_status(ctx, arn, {"DELETED"}, timeout_s=60)
    assert deleted_status == "DELETED", f"expected CA to reach DELETED after delete, got {deleted_status!r}"

    client.restore_certificate_authority(CertificateAuthorityArn=arn)

    restored_status = _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE"}, timeout_s=60)
    assert restored_status == "PENDING_CERTIFICATE", (
        f"expected restore to return the CA to its pre-delete PENDING_CERTIFICATE status, "
        f"got {restored_status!r}"
    )


def _create_ca(ctx) -> str:
    client = ctx.client("acm-pca")
    cn = ctx.unique_name("sim2real-pca-")
    resp = client.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": _KEY_ALGORITHM,
            "SigningAlgorithm": _SIGNING_ALGORITHM,
            "Subject": {"CommonName": cn[:64]},
        },
        CertificateAuthorityType="ROOT",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    return resp["CertificateAuthorityArn"]


def _wait_for_status(ctx, arn, target_statuses, timeout_s=90.0, interval_s=3.0):
    client = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"status never reached {target_statuses}, last seen {last}")


def _best_effort_delete(ctx, arn) -> None:
    client = ctx.client("acm-pca")
    try:
        status = client.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "DELETED":
        return
    if status == "ACTIVE":
        client.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
        _wait_for_status(ctx, arn, {"DISABLED"}, timeout_s=60)
    client.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
