"""restore-certificate-authority-active-state-unchanged."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags


CHECK = "restore-certificate-authority-active-state-unchanged"
GROUP = "state-machine"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RestoreCertificateAuthority on an ACTIVE CA succeeds as a no-op and leaves its
    state untouched, while a DELETED CA still restores to its pre-deletion status
    (positive control)."""
    acmpca = ctx.client("acm-pca")

    # Overly-permissive control: an ARN that never identified any CA at all must
    # still be rejected -- the no-op below must not turn into "any ARN goes".
    fake_arn = _fake_ca_arn(ctx)
    fake_code, fake_message = _error(lambda: acmpca.restore_certificate_authority(CertificateAuthorityArn=fake_arn))
    assert fake_code == "ResourceNotFoundException", f"expected ResourceNotFoundException for a nonexistent CA, got {fake_code!r}"
    assert fake_message == "Could not find specified CA", f"unexpected ResourceNotFoundException message: {fake_message!r}"

    ca_arn = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))
    _activate_root_ca(ctx, ca_arn)
    status_before = _status(ctx, ca_arn)
    assert status_before == "ACTIVE", f"expected freshly-activated CA to be ACTIVE, got {status_before!r}"

    # A no-op success: any ClientError here fails the check.
    acmpca.restore_certificate_authority(CertificateAuthorityArn=ca_arn)

    # (b) effect absent: restoring a non-DELETED CA is a no-op -- it stays ACTIVE.
    status_after_noop = _status(ctx, ca_arn)
    assert status_after_noop == "ACTIVE", f"expected no-op restore to leave CA ACTIVE, got {status_after_noop!r}"

    # (c) positive control: restore genuinely works on a CA that is actually DELETED.
    acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DISABLED", timeout_s=60)
    acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DELETED", timeout_s=60)

    acmpca.restore_certificate_authority(CertificateAuthorityArn=ca_arn)
    restored_status = _poll_until(lambda: _status(ctx, ca_arn), lambda s: s != "DELETED", timeout_s=60)
    assert restored_status == "DISABLED", f"expected restore of a DELETED CA to revert to its pre-deletion status DISABLED, got {restored_status!r}"


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


def _fake_ca_arn(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    region = acmpca.meta.region_name
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:acm-pca:{region}:{account}:certificate-authority/00000000-0000-0000-0000-000000000000"


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


def _activate_root_ca(ctx, ca_arn: str) -> None:
    """Drive a freshly created ROOT CA from PENDING_CERTIFICATE to ACTIVE by
    self-issuing (via the RootCACertificate template) and importing its own
    root certificate -- the documented AWS CLI workflow for root CA install."""
    acmpca = ctx.client("acm-pca")
    from botocore.exceptions import ClientError

    def _get_csr():
        try:
            return acmpca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)["Csr"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    csr = _poll_until(_get_csr, lambda v: v is not None, timeout_s=60)
    issue_resp = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr.encode("utf-8"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 365, "Type": "DAYS"},
    )
    cert_arn = issue_resp["CertificateArn"]

    def _get_cert():
        try:
            return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "RequestInProgressException":
                return None
            raise

    cert_pem = _poll_until(_get_cert, lambda v: v is not None, timeout_s=60)
    acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=cert_pem.encode("utf-8")
    )
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "ACTIVE", timeout_s=60)


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
