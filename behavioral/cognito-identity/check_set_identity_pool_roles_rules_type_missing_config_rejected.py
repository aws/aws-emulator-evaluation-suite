"""set-identity-pool-roles-rules-type-missing-config-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "set-identity-pool-roles-rules-type-missing-config-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises, and fail if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A RoleMapping of Type=Rules with no RulesConfiguration is rejected as malformed input."""
    iam = ctx.client("iam")
    cip = ctx.client("cognito-identity")

    pool_id = cip.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={"graph.facebook.com": "1234567890123456"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-behav-cirole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "unauthenticated"
                },
            },
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    provider_key = "graph.facebook.com"

    def _bad_call():
        cip.set_identity_pool_roles(
            IdentityPoolId=pool_id,
            Roles={"unauthenticated": role_arn},
            RoleMappings={
                provider_key: {
                    "Type": "Rules",
                    "AmbiguousRoleResolution": "AuthenticatedRole",
                    # RulesConfiguration intentionally omitted -- required for Type=Rules
                }
            },
        )

    code, message = _error(_bad_call)
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "RuleConfiguration is required for Rules", (
        f"expected the exact refusal message AWS returns, got {message!r}"
    )

    # effect absent: no role-mapping configuration was persisted for the pool
    current = cip.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert current.get("RoleMappings", {}) == {}, "malformed RoleMappings must not persist"

    # positive control: the identical call, but WITH a valid RulesConfiguration, succeeds
    cip.set_identity_pool_roles(
        IdentityPoolId=pool_id,
        Roles={"unauthenticated": role_arn},
        RoleMappings={
            provider_key: {
                "Type": "Rules",
                "AmbiguousRoleResolution": "AuthenticatedRole",
                "RulesConfiguration": {
                    "Rules": [
                        {
                            "Claim": "isAdmin",
                            "MatchType": "Equals",
                            "Value": "true",
                            "RoleARN": role_arn,
                        }
                    ]
                },
            }
        },
    )
    after = cip.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert provider_key in after.get("RoleMappings", {}), "valid RoleMappings must persist"
    assert after["RoleMappings"][provider_key]["Type"] == "Rules", (
        f"expected the restored Rules mapping to persist, got {after.get('RoleMappings')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
