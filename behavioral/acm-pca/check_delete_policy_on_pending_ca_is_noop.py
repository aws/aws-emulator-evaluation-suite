"""delete-policy-on-pending-ca-is-noop."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-policy-on-pending-ca-is-noop"
GROUP = "state-machine"
SERVICES = ["acm-pca"]

_KEY_ALGORITHM = "RSA_2048"
_SIGNING_ALGORITHM = "SHA256WITHRSA"
_ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePolicy refuses a fabricated CA ARN with ResourceNotFoundException, succeeds as a
    no-op on a PENDING_CERTIFICATE CA without a policy, and on an ACTIVE CA removes the
    attached policy so GetPolicy then fails."""
    client = ctx.client("acm-pca")

    # Overly-permissive control: DeletePolicy against an ARN that does not correspond
    # to any CA at all must fail, not silently succeed.
    fake_arn = _fake_ca_arn(ctx)
    code = _error_code(lambda: client.delete_policy(ResourceArn=fake_arn))
    assert code == ("ResourceNotFoundException", "Could not find specified CA"), code

    pending_arn = _create_ca(ctx)
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, pending_arn))
    _wait_for_status(ctx, pending_arn, {"PENDING_CERTIFICATE"}, timeout_s=90)

    # DeletePolicy against a real, existing CA that never had a policy attached does
    # NOT raise -- it is a no-op, not a hard failure.
    client.delete_policy(ResourceArn=pending_arn)

    # Independent read proving the no-op really left no policy behind (not merely that
    # the call itself did not raise).
    noop_code = _error_code(lambda: client.get_policy(ResourceArn=pending_arn))
    assert noop_code == ("ResourceNotFoundException", "Could not find policy for specified resource."), f"expected no policy after no-op delete, got {noop_code!r}"

    # Positive control: an ACTIVE CA with a real attached policy really can have that
    # policy deleted, in the same file. Principal must be a real, existing AWS account
    # (the caller's own account satisfies that trivially).
    account_id = client_sts_account(ctx)
    active_arn = _create_ca(ctx)
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, active_arn))
    _activate_root_ca(ctx, active_arn)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": ["acm-pca:DescribeCertificateAuthority"],
                "Resource": active_arn,
            }
        ],
    }
    client.put_policy(ResourceArn=active_arn, Policy=json.dumps(policy))
    client.get_policy(ResourceArn=active_arn)  # confirm the attach actually took effect
    client.delete_policy(ResourceArn=active_arn)
    control_code = _error_code(lambda: client.get_policy(ResourceArn=active_arn))
    assert control_code == ("ResourceNotFoundException", "Could not find policy for specified resource."), (
        f"expected the attached policy to be gone after a real DeletePolicy, got {control_code!r}"
    )


def _fake_ca_arn(ctx) -> str:
    client = ctx.client("acm-pca")
    region = client.meta.region_name
    account = client_sts_account(ctx)
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


def _error_code(fn) -> tuple[str, str]:
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def client_sts_account(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
