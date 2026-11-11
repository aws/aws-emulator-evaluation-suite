"""restore-certificate-authority-active-ca-succeeds-as-noop."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "restore-certificate-authority-active-ca-succeeds-as-noop"
GROUP = "state-machine"
SERVICES = ["acm-pca"]

_KEY_ALGORITHM = "RSA_2048"
_SIGNING_ALGORITHM = "SHA256WITHRSA"
_ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """RestoreCertificateAuthority on a nonexistent CA ARN fails with ResourceNotFoundException;
    on an ACTIVE CA it is a no-op that leaves it ACTIVE; a DELETED CA is restored."""
    client = ctx.client("acm-pca")

    # Overly-permissive control: restoring an ARN that does not correspond to any CA
    # at all must fail, not silently succeed.
    fake_arn = _fake_ca_arn(ctx)
    code, message = _error(lambda: client.restore_certificate_authority(CertificateAuthorityArn=fake_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Could not find specified CA", f"unexpected ResourceNotFoundException message: {message!r}"

    active_arn = _create_ca(ctx)
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, active_arn))
    _activate_root_ca(ctx, active_arn)
    status_before = client.describe_certificate_authority(CertificateAuthorityArn=active_arn)[
        "CertificateAuthority"
    ]["Status"]
    assert status_before == "ACTIVE", f"expected ACTIVE before the no-op restore, got {status_before!r}"

    # A real, existing ACTIVE CA is not in DELETED state, so restore is a no-op: it
    # must not raise, and must not change the CA's status.
    client.restore_certificate_authority(CertificateAuthorityArn=active_arn)

    status_after = client.describe_certificate_authority(CertificateAuthorityArn=active_arn)[
        "CertificateAuthority"
    ]["Status"]
    assert status_after == "ACTIVE", f"expected ACTIVE unchanged after the no-op restore, got {status_after!r}"

    # Positive control: a really deleted CA is restored, so restore is not an unconditional no-op.
    control_arn = _create_ca(ctx)
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, control_arn))
    _wait_for_status(ctx, control_arn, {"PENDING_CERTIFICATE"}, timeout_s=90)
    client.delete_certificate_authority(CertificateAuthorityArn=control_arn, PermanentDeletionTimeInDays=7)
    _wait_for_status(ctx, control_arn, {"DELETED"}, timeout_s=60)
    client.restore_certificate_authority(CertificateAuthorityArn=control_arn)
    restored = _wait_for_status(ctx, control_arn, {"PENDING_CERTIFICATE"}, timeout_s=60)
    assert restored == "PENDING_CERTIFICATE", (
        f"expected restore to revive the DELETED CA back to PENDING_CERTIFICATE, got {restored!r}"
    )


def _fake_ca_arn(ctx) -> str:
    client = ctx.client("acm-pca")
    region = client.meta.region_name
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:acm-pca:{region}:{account}:certificate-authority/00000000-0000-0000-0000-000000000000"


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _wait_for_certificate(ctx, ca_arn, cert_arn, timeout_s=90.0, interval_s=3.0):
    client = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return client.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "RequestInProgressException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"certificate never became available, last error: {last_code}")


def _activate_root_ca(ctx, arn) -> None:
    client = ctx.client("acm-pca")
    _wait_for_status(ctx, arn, {"PENDING_CERTIFICATE"}, timeout_s=90)
    csr = client.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"]
    cert_arn = client.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr,
        SigningAlgorithm=_SIGNING_ALGORITHM,
        TemplateArn=_ROOT_TEMPLATE_ARN,
        Validity={"Value": 365, "Type": "DAYS"},
    )["CertificateArn"]
    cert_pem = _wait_for_certificate(ctx, arn, cert_arn)
    client.import_certificate_authority_certificate(CertificateAuthorityArn=arn, Certificate=cert_pem)
    _wait_for_status(ctx, arn, {"ACTIVE"}, timeout_s=90)


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


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
