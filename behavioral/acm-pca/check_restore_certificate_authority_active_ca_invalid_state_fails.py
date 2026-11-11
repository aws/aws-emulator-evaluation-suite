"""restore-certificate-authority-active-ca-invalid-state-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "restore-certificate-authority-active-ca-invalid-state-fails"
GROUP = "state-machine"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RestoreCertificateAuthority on a CA that is not DELETED succeeds as a no-op leaving its
    status unchanged, while restoring a DELETED CA returns it to PENDING_CERTIFICATE."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    _register_ca_cleanup(ctx, ca_arn)
    status = _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"})
    assert status == "PENDING_CERTIFICATE", f"expected freshly created CA to be PENDING_CERTIFICATE, got {status!r}"

    # Restoring a never-deleted CA does not raise and leaves its state unchanged.
    acmpca.restore_certificate_authority(CertificateAuthorityArn=ca_arn)
    status = _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"}, timeout_s=10)
    assert status == "PENDING_CERTIFICATE", f"expected no-op restore to leave CA PENDING_CERTIFICATE, got {status!r}"

    # Positive control: delete this same CA (allowed from PENDING_CERTIFICATE),
    # then restore it -- this time the call actually changes state.
    acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
    status = _wait_for_ca_status(ctx, ca_arn, {"DELETED"})
    assert status == "DELETED", f"expected delete to move CA to DELETED, got {status!r}"
    acmpca.restore_certificate_authority(CertificateAuthorityArn=ca_arn)
    status = _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"})
    assert status == "PENDING_CERTIFICATE", f"expected restore of a DELETED CA to revert to PENDING_CERTIFICATE, got {status!r}"

    # Calling restore again now that the CA is back to PENDING_CERTIFICATE
    # (not DELETED) is again a no-op: no exception, no state change.
    acmpca.restore_certificate_authority(CertificateAuthorityArn=ca_arn)
    status = _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"}, timeout_s=10)
    assert status == "PENDING_CERTIFICATE", f"expected second no-op restore to leave CA PENDING_CERTIFICATE, got {status!r}"



def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"]


def _create_root_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")[:64]},
        },
    )
    return resp["CertificateAuthorityArn"]


def _register_ca_cleanup(ctx, arn: str) -> None:
    acmpca = ctx.client("acm-pca")

    def _cleanup():
        try:
            status = acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status == "ACTIVE":
            acmpca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
            _wait_for_ca_status(ctx, arn, {"DISABLED"}, timeout_s=30)
            status = "DISABLED"
        if status != "DELETED":
            acmpca.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)

    ctx.on_cleanup(_cleanup)


def _wait_for_ca_status(ctx, arn: str, statuses, timeout_s: float = 90.0, interval_s: float = 2.0) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if last in statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"CA {arn} never reached {statuses}, last status={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
