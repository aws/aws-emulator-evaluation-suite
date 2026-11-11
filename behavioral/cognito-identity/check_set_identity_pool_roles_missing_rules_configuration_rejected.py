"""set-identity-pool-roles-missing-rules-configuration-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-identity-pool-roles-missing-rules-configuration-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIdentityPoolRoles rejects a RoleMapping of Type=Rules that omits RulesConfiguration, and
    leaves the pool's existing role configuration untouched; a well-formed Rules mapping for the
    same provider is accepted and visible via GetIdentityPoolRoles."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        SupportedLoginProviders={"graph.facebook.com": "sim2real-behav-fb-app-id"},
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    provider_name = "graph.facebook.com"

    # Baseline: no RoleMappings configured for this provider yet.
    baseline = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert provider_name not in baseline.get("RoleMappings", {}), (
        f"expected no RoleMappings for {provider_name} on a freshly created pool, "
        f"got {baseline.get('RoleMappings', {})!r}"
    )

    def _set_broken_mapping():
        ci.set_identity_pool_roles(
            IdentityPoolId=pool_id,
            Roles={"authenticated": role_arn},
            RoleMappings={
                provider_name: {
                    "Type": "Rules",
                    "AmbiguousRoleResolution": "AuthenticatedRole",
                    # RulesConfiguration deliberately omitted.
                }
            },
        )

    code, message = _error(_set_broken_mapping)
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == "RuleConfiguration is required for Rules", (
        f"expected the exact refusal message AWS returns, got {message!r}"
    )

    # Effect absent: the broken call did not partially apply (no RoleMappings persisted).
    after_broken = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert provider_name not in after_broken.get("RoleMappings", {}), (
        "the rejected RoleMapping was nonetheless persisted"
    )

    # Positive control: a well-formed Rules mapping for the same provider is accepted.
    ci.set_identity_pool_roles(
        IdentityPoolId=pool_id,
        Roles={"authenticated": role_arn},
        RoleMappings={
            provider_name: {
                "Type": "Rules",
                "AmbiguousRoleResolution": "AuthenticatedRole",
                "RulesConfiguration": {
                    "Rules": [
                        {"Claim": "iss", "MatchType": "Contains", "Value": "facebook", "RoleARN": role_arn},
                    ]
                },
            }
        },
    )
    after_valid = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert after_valid["RoleMappings"][provider_name]["Type"] == "Rules", (
        f"expected a well-formed Rules mapping for {provider_name} to persist, "
        f"got {after_valid.get('RoleMappings', {}).get(provider_name)!r}"
    )


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises, and fail if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
