"""set-identity-pool-roles-ambiguous-rule-resolution-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-identity-pool-roles-ambiguous-rule-resolution-rejected"
GROUP = "negative-classes"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIdentityPoolRoles with a RoleMapping of Type=Rules but no RulesConfiguration
    (so rule resolution is undefined/ambiguous) is rejected as InvalidParameterException,
    and the pool's previously-persisted role mapping is left untouched."""
    cip = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_name = ctx.unique_name("sim2real-behav-cogid-")
    pool_id = cip.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        SupportedLoginProviders={"graph.facebook.com": "1234567890123456"},
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cip.delete_identity_pool(IdentityPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-behav-cogid-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                        "ForAnyValue:StringLike": {
                            "cognito-identity.amazonaws.com:amr": "*"
                        },
                    },
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    roles = {"authenticated": role_arn, "unauthenticated": role_arn}

    # Positive control: a valid Rules-type role mapping with a real RulesConfiguration
    # is accepted and persisted. (IAM role propagation can lag briefly after
    # create_role -- retry.)
    _set_roles_with_retry(
        cip,
        pool_id,
        roles,
        {
            "graph.facebook.com": {
                "Type": "Rules",
                "AmbiguousRoleResolution": "AuthenticatedRole",
                "RulesConfiguration": {
                    "Rules": [
                        {
                            "Claim": "sim2real_claim",
                            "MatchType": "Equals",
                            "Value": "sim2real-value",
                            "RoleARN": role_arn,
                        }
                    ]
                },
            }
        },
    )
    persisted = cip.get_identity_pool_roles(IdentityPoolId=pool_id)
    persisted_mapping = persisted["RoleMappings"]["graph.facebook.com"]
    assert persisted_mapping["Type"] == "Rules", (
        f"expected the well-formed positive control to persist Type=Rules, got {persisted_mapping!r}"
    )
    persisted_rules = persisted_mapping["RulesConfiguration"]["Rules"]
    assert len(persisted_rules) == 1, (
        f"expected exactly 1 rule persisted by the positive control, got {len(persisted_rules)}: {persisted_rules!r}"
    )

    # Break exactly one thing: Type=Rules with no RulesConfiguration at all, so there
    # is nothing to resolve the mapping against.
    code, message = _error(
        lambda: cip.set_identity_pool_roles(
            IdentityPoolId=pool_id,
            Roles=roles,
            RoleMappings={
                "graph.facebook.com": {
                    "Type": "Rules",
                    "AmbiguousRoleResolution": "AuthenticatedRole",
                }
            },
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for Type=Rules with no RulesConfiguration, got {code!r}"
    )
    assert message == "RuleConfiguration is required for Rules", (
        f"expected the exact refusal message AWS returns, got {message!r}"
    )

    # Effect absent: the rejected update did not overwrite the persisted mapping.
    unchanged = cip.get_identity_pool_roles(IdentityPoolId=pool_id)
    unchanged_mapping = unchanged["RoleMappings"]["graph.facebook.com"]
    assert unchanged_mapping["Type"] == "Rules", (
        f"expected the rejected call to leave the persisted mapping untouched, got {unchanged_mapping!r}"
    )
    unchanged_rules = unchanged_mapping["RulesConfiguration"]["Rules"]
    assert len(unchanged_rules) == 1, (
        f"expected the pre-existing rule to survive the rejected call, got {len(unchanged_rules)}: {unchanged_rules!r}"
    )


def _error(fn):
    """Call fn(); return (Code, Message) of the ClientError it raises, and fail if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _set_roles_with_retry(cip, pool_id, roles, role_mappings, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cip.set_identity_pool_roles(
                IdentityPoolId=pool_id, Roles=roles, RoleMappings=role_mappings
            )
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(1.5)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
