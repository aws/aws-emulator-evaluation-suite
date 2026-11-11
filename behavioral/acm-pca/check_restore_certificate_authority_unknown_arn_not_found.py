"""restore-certificate-authority-unknown-arn-not-found."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "restore-certificate-authority-unknown-arn-not-found"
GROUP = "state-machine"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreCertificateAuthority with a well-formed but nonexistent CA ARN
    returns ResourceNotFoundException, and a real CA's delete/restore cycle
    still works in the same file (positive control).
    """
    acmpca = ctx.client("acm-pca")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:acm-pca:{ctx.region}:{account_id}:certificate-authority/{uuid.uuid4()}"

    code, message = _error(lambda: acmpca.restore_certificate_authority(CertificateAuthorityArn=bogus_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException for a never-issued CA arn, got {code!r}"
    assert message == "Could not find specified CA", f"unexpected ResourceNotFoundException message: {message!r}"

    # Positive control: a genuinely existing, genuinely deleted CA can be restored.
    ca_arn = _create_root_ca(ctx)
    _register_ca_cleanup(ctx, ca_arn)
    status = _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"})
    assert status == "PENDING_CERTIFICATE", f"expected a freshly created CA to reach PENDING_CERTIFICATE, got {status!r}"
    acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
    status = _wait_for_ca_status(ctx, ca_arn, {"DELETED"})
    assert status == "DELETED", f"expected the CA to reach DELETED after delete_certificate_authority, got {status!r}"
    acmpca.restore_certificate_authority(CertificateAuthorityArn=ca_arn)
    status = _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"})
    assert status == "PENDING_CERTIFICATE", f"expected restore_certificate_authority on the real, DELETED CA to bring it back to PENDING_CERTIFICATE, got {status!r}"



def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
