"""eab-revoke-already-deleted-conflicts."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eab-revoke-already-deleted-conflicts"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-revoking a revoked EAB succeeds and leaves RevokedAt unchanged; revoking a deleted EAB
    fails with ResourceNotFoundException and does not bring the binding back."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx)
    role_arn = _create_acme_role(ctx)

    # Case (a): revoke an already-revoked binding is an idempotent no-op.
    eab_arn_a, _created_a = _create_eab(ctx, endpoint_arn, role_arn)
    acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn_a)
    revoked_state = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn_a)[
        "ExternalAccountBinding"
    ]
    assert revoked_state.get("RevokedAt") is not None, "first revoke must set RevokedAt"
    first_revoked_at = revoked_state["RevokedAt"]

    # Idempotent success: a refusal here raises ClientError and fails the check.
    acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn_a)

    unchanged_state = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn_a)[
        "ExternalAccountBinding"
    ]
    assert unchanged_state["RevokedAt"] == first_revoked_at, "idempotent re-revoke must not move RevokedAt"

    # Case (b): revoke a binding that was already deleted -> ResourceNotFoundException.
    eab_arn_b, _created_b = _create_eab(ctx, endpoint_arn, role_arn)
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn_b)

    code_b, message_b = _error(
        lambda: acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn_b)
    )
    assert code_b == "ResourceNotFoundException", f"expected ResourceNotFoundException revoking a deleted EAB, got {code_b}"
    expected_message = f"Could not find ACME external account binding {eab_arn_b}."
    assert message_b == expected_message, f"expected message {expected_message!r}, got {message_b!r}"

    remaining = acm.list_acme_external_account_bindings(AcmeEndpointArn=endpoint_arn).get(
        "ExternalAccountBindings", []
    )
    arns = [b["AcmeExternalAccountBindingArn"] for b in remaining]
    assert eab_arn_b not in arns, "the rejected revoke must not resurrect the deleted binding"


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        "ACME endpoint did not reach ACTIVE status within timeout"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
            ctx.on_cleanup(lambda a=arn: _safe_delete_eab(ctx, a))
            return arn, binding
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "AccessDeniedException":
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create EAB after IAM role propagation retries: {last_err}")


def _safe_delete_eab(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
