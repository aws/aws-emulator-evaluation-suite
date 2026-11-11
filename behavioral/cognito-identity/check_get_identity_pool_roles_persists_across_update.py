"""get-identity-pool-roles-persists-across-update."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "get-identity-pool-roles-persists-across-update"
GROUP = "state-machine"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Role mappings survive an unrelated UpdateIdentityPool call that doesn't touch roles."""
    client = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_id = _create_pool(ctx, client)
    role_arn = _create_unauth_role(ctx, iam, pool_id)
    roles = {"unauthenticated": role_arn, "authenticated": role_arn}
    client.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=roles)

    before = client.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert before["Roles"] == roles, f"role mappings not persisted right after SetIdentityPoolRoles: {before}"

    described = client.describe_identity_pool(IdentityPoolId=pool_id)
    new_classic_flow = not described.get("AllowClassicFlow", False)
    client.update_identity_pool(
        IdentityPoolId=pool_id,
        IdentityPoolName=described["IdentityPoolName"],
        AllowUnauthenticatedIdentities=described["AllowUnauthenticatedIdentities"],
        AllowClassicFlow=new_classic_flow,
    )

    # confirm the unrelated field really did change, proving UpdateIdentityPool took effect
    updated = client.describe_identity_pool(IdentityPoolId=pool_id)
    assert updated["AllowClassicFlow"] == new_classic_flow, "UpdateIdentityPool did not apply the field change"

    after = client.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert after["Roles"] == roles, (
        f"role mappings changed after an unrelated UpdateIdentityPool call: before={roles} after={after['Roles']}"
    )


def _create_pool(ctx, client, **extra_fields: Any) -> str:
    params = {
        "IdentityPoolName": ctx.unique_name("sim2real-idp-"),
        "AllowUnauthenticatedIdentities": True,
        "IdentityPoolTags": {"sim2real": CHECK},
    }
    params.update(extra_fields)
    pool_id = client.create_identity_pool(**params)["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _create_unauth_role(ctx, iam_client, pool_id: str) -> str:
    role_name = ctx.unique_name("sim2real-cog-unauth-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {
                        "cognito-identity.amazonaws.com:amr": "unauthenticated"
                    },
                },
            }
        ],
    }
    resp = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        MaxSessionDuration=3600,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam_client.delete_role(RoleName=role_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
