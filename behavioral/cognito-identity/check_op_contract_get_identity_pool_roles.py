"""op-contract-getIdentityPoolRoles."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-getIdentityPoolRoles"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetIdentityPoolRoles reflects the roles configured via SetIdentityPoolRoles
    (empty by default), and raises ResourceNotFoundException for an unknown pool."""
    cidp = ctx.client("cognito-identity")
    pool_id = _create_identity_pool(ctx, allow_unauth=True)

    # success path, baseline: no roles configured yet
    baseline = cidp.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert baseline["IdentityPoolId"] == pool_id, (
        f"expected IdentityPoolId {pool_id}, got {baseline.get('IdentityPoolId')}"
    )
    assert not baseline.get("Roles"), f"expected no roles configured yet, got {baseline.get('Roles')}"

    role_arn = _create_trust_role_for_pool(ctx, pool_id)
    cidp.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"authenticated": role_arn})

    configured = cidp.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert configured["Roles"].get("authenticated") == role_arn, (
        f"expected authenticated role {role_arn}, got {configured['Roles'].get('authenticated')}"
    )

    # error boundary: well-formed IdentityPoolId that was never created
    bogus_id = f"{ctx.region}:00000000-0000-0000-0000-000000000000"
    code, message = _error(lambda: cidp.get_identity_pool_roles(IdentityPoolId=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"IdentityPool '{bogus_id}' not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _create_identity_pool(ctx, *, allow_unauth: bool) -> str:
    cidp = ctx.client("cognito-identity")
    pool = cidp.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=allow_unauth,
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cidp.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _create_trust_role_for_pool(ctx, pool_id: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cidp-role-")
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
                        "cognito-identity.amazonaws.com:amr": "authenticated"
                    },
                },
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _error(fn) -> tuple[str, str | None]:
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
