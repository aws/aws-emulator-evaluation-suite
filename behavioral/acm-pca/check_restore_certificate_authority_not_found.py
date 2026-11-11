"""restore-certificate-authority-not-found."""
from __future__ import annotations

import time
import uuid
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "restore-certificate-authority-not-found"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreCertificateAuthority with a well-formed but non-existent CA
    ARN returns ResourceNotFoundException; a real DELETED CA in the same
    account/region still restores successfully (positive control)."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    ctx.on_cleanup(lambda: _safe_delete_ca(ctx, ca_arn))

    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s in ("PENDING_CERTIFICATE", "FAILED"), timeout_s=60)
    acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
    _poll_until(lambda: _status(ctx, ca_arn), lambda s: s == "DELETED", timeout_s=60)

    partition, _svc, service, region, account, _rest = ca_arn.split(":", 5)
    nonexistent_arn = f"{partition}:{_svc}:{service}:{region}:{account}:certificate-authority/{uuid.uuid4()}"

    code, message = _error(lambda: acmpca.restore_certificate_authority(CertificateAuthorityArn=nonexistent_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Could not find specified CA", f"unexpected ResourceNotFoundException message: {message!r}"

    # effect absent: the real CA (an unrelated resource) is untouched by the rejected call.
    unaffected_status = _status(ctx, ca_arn)
    assert unaffected_status == "DELETED", f"expected real CA to remain DELETED after rejected call, got {unaffected_status}"

    # positive control: the real, well-formed, existing CA ARN restores successfully.
    acmpca.restore_certificate_authority(CertificateAuthorityArn=ca_arn)
    restored_status = _poll_until(lambda: _status(ctx, ca_arn), lambda s: s != "DELETED", timeout_s=60)
    assert restored_status == "PENDING_CERTIFICATE", f"expected restored CA status PENDING_CERTIFICATE, got {restored_status}"


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
