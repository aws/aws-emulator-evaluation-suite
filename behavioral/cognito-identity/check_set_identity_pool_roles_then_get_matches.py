"""set-identity-pool-roles-then-get-matches."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "set-identity-pool-roles-then-get-matches"
GROUP = "roles"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIdentityPoolRoles persists both the Roles map and RoleMappings; GetIdentityPoolRoles
    reads back exactly what was configured."""
    iam = ctx.client("iam")
    ci = ctx.client("cognito-identity")

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={"graph.facebook.com": "1234567890123456"},
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-behav-role-")
    # Real AWS's IAM validates the "aud" condition value against the well-known
    # cognito-identity.amazonaws.com audience shape (a real identity pool id) -- a wildcard
    # "*" is rejected as a malformed trust policy, so scope it to the pool we just created.
    trust_policy = _trust_policy_document(ctx, pool_id)
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    _set_roles_with_retry(
        ci,
        pool_id,
        Roles={"authenticated": role_arn, "unauthenticated": role_arn},
        RoleMappings={
            "graph.facebook.com": {
                "Type": "Rules",
                "AmbiguousRoleResolution": "Deny",
                "RulesConfiguration": {
                    "Rules": [
                        {
                            "Claim": "email",
                            "MatchType": "Contains",
                            "Value": "example.com",
                            "RoleARN": role_arn,
                        }
                    ]
                },
            }
        },
    )

    expected_roles = {"authenticated": role_arn, "unauthenticated": role_arn}
    got = _get_roles_with_retry(ci, pool_id, expected_roles)
    assert got["Roles"] == expected_roles, f"expected Roles {expected_roles}, got {got.get('Roles')}"
    mapping = got["RoleMappings"]["graph.facebook.com"]
    assert mapping["Type"] == "Rules", f"expected Type Rules, got {mapping.get('Type')}"
    assert mapping["AmbiguousRoleResolution"] == "Deny", (
        f"expected AmbiguousRoleResolution Deny, got {mapping.get('AmbiguousRoleResolution')}"
    )
    rules = mapping["RulesConfiguration"]["Rules"]
    assert len(rules) == 1, f"expected exactly 1 rule, got {rules}"
    assert rules[0]["Claim"] == "email", f"expected Claim email, got {rules[0].get('Claim')}"
    assert rules[0]["MatchType"] == "Contains", f"expected MatchType Contains, got {rules[0].get('MatchType')}"
    assert rules[0]["Value"] == "example.com", f"expected Value example.com, got {rules[0].get('Value')}"
    assert rules[0]["RoleARN"] == role_arn, f"expected RoleARN {role_arn}, got {rules[0].get('RoleARN')}"


def _trust_policy_document(ctx, pool_id: str) -> str:
    import json

    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}
                    },
                }
            ],
        }
    )


def _set_roles_with_retry(ci, pool_id, **kwargs):
    """A freshly-created IAM role can take a few seconds to propagate; SetIdentityPoolRoles
    may reject the role ARN in the meantime, so retry briefly instead of failing outright."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.time() + 30
    while True:
        try:
            return ci.set_identity_pool_roles(IdentityPoolId=pool_id, **kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("InvalidParameterException", "ValidationException") or time.time() >= deadline:
                raise
            time.sleep(2)


def _get_roles_with_retry(ci, pool_id, expected_roles, timeout_s=20.0, interval_s=2.0):
    """GetIdentityPoolRoles is eventually consistent right after SetIdentityPoolRoles: the very
    next read can transiently omit Roles or return a stale RoleMappings, so poll for the readback
    to reflect what was just set instead of asserting on the first response."""
    import time

    deadline = time.time() + timeout_s
    last = None
    while True:
        last = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
        if last.get("Roles") == expected_roles and "graph.facebook.com" in last.get("RoleMappings", {}):
            return last
        if time.time() >= deadline:
            return last
        time.sleep(interval_s)



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
