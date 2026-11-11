"""delete-policy-removes-resource-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-policy-removes-resource-policy"
GROUP = "state-machine"
SERVICES = ["acm-pca"]

_KEY_ALGORITHM = "RSA_2048"
_SIGNING_ALGORITHM = "SHA256WITHRSA"
_ROOT_TEMPLATE_ARN = "arn:aws:acm-pca:::template/RootCACertificate/V1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePolicy on a CA with an attached resource policy removes it such that a
    subsequent GetPolicy returns ResourceNotFoundException instead of the stale
    document."""
    client = ctx.client("acm-pca")
    arn = _create_ca(ctx)
    ctx.on_cleanup(lambda: _best_effort_delete(ctx, arn))
    client.tag_certificate_authority(CertificateAuthorityArn=arn, Tags=[{"Key": "sim2real", "Value": "1"}])
    _activate_root_ca(ctx, arn)

    # Principal must be a real, existing AWS account -- the caller's own account
    # satisfies that trivially and is sufficient to exercise the policy lifecycle.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy = _resource_policy(arn, account_id=account_id)
    client.put_policy(ResourceArn=arn, Policy=json.dumps(policy))

    attached = json.loads(client.get_policy(ResourceArn=arn)["Policy"])
    mismatch = _policy_mismatch(policy, attached)
    assert mismatch is None, f"GetPolicy echo mismatch: {mismatch}; put {policy!r}, got {attached!r}"

    client.delete_policy(ResourceArn=arn)

    code = _error_code(lambda: client.get_policy(ResourceArn=arn))
    assert code == ("ResourceNotFoundException", "Could not find policy for specified resource."), (
        f"expected GetPolicy to fail with ResourceNotFoundException after DeletePolicy, got {code!r}"
    )


def _policy_mismatch(expected: dict, actual: dict) -> str | None:
    """Compare a PutPolicy document against its GetPolicy echo.

    AWS Private CA canonicalizes an account-id Principal to its
    root-user ARN and collapses a single-element Action list to a bare string, so a
    literal dict `==` is the wrong comparison -- it fails against a correctly-behaving
    target.
    """
    if expected.get("Version") != actual.get("Version"):
        return f"Version: expected {expected.get('Version')!r}, got {actual.get('Version')!r}"
    exp_stmts, act_stmts = expected["Statement"], actual.get("Statement", [])
    if len(exp_stmts) != len(act_stmts):
        return f"expected {len(exp_stmts)} statements, got {len(act_stmts)}"
    for exp, act in zip(exp_stmts, act_stmts):
        sid = exp["Sid"]
        if act.get("Sid") != sid:
            return f"statement Sid: expected {sid!r}, got {act.get('Sid')!r}"
        if act.get("Effect") != exp["Effect"]:
            return f"{sid} Effect: expected {exp['Effect']!r}, got {act.get('Effect')!r}"
        if act.get("Resource") != exp["Resource"]:
            return f"{sid} Resource: expected {exp['Resource']!r}, got {act.get('Resource')!r}"
        if act.get("Condition") != exp.get("Condition"):
            return f"{sid} Condition: expected {exp.get('Condition')!r}, got {act.get('Condition')!r}"
        exp_actions = sorted(exp["Action"]) if isinstance(exp["Action"], list) else [exp["Action"]]
        act_action = act.get("Action")
        act_actions = sorted(act_action) if isinstance(act_action, list) else [act_action]
        if act_actions != exp_actions:
            return f"{sid} Action: expected {exp_actions!r}, got {act_actions!r}"
        exp_principal_aws = exp["Principal"]["AWS"]
        act_principal_aws = act.get("Principal", {}).get("AWS")
        if act_principal_aws not in (exp_principal_aws, f"arn:aws:iam::{exp_principal_aws}:root"):
            return f"{sid} Principal.AWS: expected {exp_principal_aws!r} (bare or root-ARN form), got {act_principal_aws!r}"
    return None


def _resource_policy(ca_arn: str, account_id: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": [
                    "acm-pca:DescribeCertificateAuthority",
                    "acm-pca:GetCertificate",
                    "acm-pca:GetCertificateAuthorityCertificate",
                    "acm-pca:ListPermissions",
                    "acm-pca:ListTags",
                ],
                "Resource": ca_arn,
            },
            {
                "Sid": "AllowIssue",
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": ["acm-pca:IssueCertificate"],
                "Resource": ca_arn,
                "Condition": {
                    "StringEquals": {
                        "acm-pca:TemplateArn": "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
                    }
                },
            },
        ],
    }


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
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
