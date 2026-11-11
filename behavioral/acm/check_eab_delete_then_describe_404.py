"""eab-delete-then-describe-404."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eab-delete-then-describe-404"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteAcmeExternalAccountBinding removes a binding, a subsequent
    DescribeAcmeExternalAccountBinding fails with ResourceNotFoundException rather
    than returning stale data, and the binding disappears from the list too."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx)
    role_arn = _create_acme_role(ctx)
    eab_arn, _created = _create_eab(ctx, endpoint_arn, role_arn)

    # Positive control: right after creation it is visible.
    described = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    described_arn = described["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
    assert described_arn == eab_arn, f"expected freshly-created EAB to describe as {eab_arn}, got {described_arn}"

    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)

    code, message = _error(
        lambda: acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code}"
    expected_message = f"Could not find ACME external account binding {eab_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    remaining = acm.list_acme_external_account_bindings(AcmeEndpointArn=endpoint_arn).get(
        "ExternalAccountBindings", []
    )
    arns = [b["AcmeExternalAccountBindingArn"] for b in remaining]
    assert eab_arn not in arns, "deleted EAB must not appear in ListAcmeExternalAccountBindings"

    # A mutation on the now-dead id must fail the same specific way, not silently no-op.
    revoke_code, revoke_message = _error(
        lambda: acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    )
    assert revoke_code == "ResourceNotFoundException", (
        f"expected RevokeAcmeExternalAccountBinding on a deleted EAB to fail with "
        f"ResourceNotFoundException, got {revoke_code}"
    )
    assert revoke_message == expected_message, (
        f"expected message {expected_message!r} from RevokeAcmeExternalAccountBinding, got {revoke_message!r}"
    )


def _error(fn):
    """Run fn, which must be refused; return the (code, message) of the refusal."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_active_endpoint(ctx) -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _safe_delete_endpoint(ctx, arn))
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        ep = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if ep["Status"] == "ACTIVE":
            return arn
        if ep["Status"] == "FAILED":
            raise AssertionError(f"ACME endpoint entered FAILED: {ep.get('FailureReason')}")
        time.sleep(3)
    raise AssertionError(
        "ACME endpoint did not reach ACTIVE status within timeout",
    )


def _safe_delete_endpoint(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _create_acme_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acme-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "acme-permissions"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"], "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_eab(ctx, endpoint_arn: str, role_arn: str) -> tuple[str, dict[str, Any]]:
    
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    last_err = None
    for _ in range(12):
        try:
            resp = acm.create_acme_external_account_binding(AcmeEndpointArn=endpoint_arn, RoleArn=role_arn)
            binding = resp["ExternalAccountBinding"]
            arn = binding["AcmeExternalAccountBindingArn"]
            return arn, binding
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "AccessDeniedException":
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create EAB after IAM role propagation retries: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
