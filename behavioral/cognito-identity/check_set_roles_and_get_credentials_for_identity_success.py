"""set-roles-and-get-credentials-for-identity-success."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-roles-and-get-credentials-for-identity-success"
GROUP = "data-plane"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SetIdentityPoolRoles wires an IAM role; GetCredentialsForIdentity yields usable STS creds for it."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_pool_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-cog-unauth-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"},
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

    # IAM trust policy propagation is eventually consistent; give it a moment.
    _poll_until(
        ctx,
        probe=lambda: _try_get_role_arn(iam, role_name),
        predicate=lambda arn: arn == role_arn,
        timeout_s=20,
        interval_s=2,
        description="IAM role visible via get_role",
    )

    ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn})

    roles_readback = ci.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert roles_readback["Roles"].get("unauthenticated") == role_arn

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]

    creds = _poll_until(
        ctx,
        probe=lambda: _try_get_credentials(ci, identity_id),
        predicate=lambda c: c is not None,
        timeout_s=60,
        interval_s=3,
        description="GetCredentialsForIdentity to succeed after role propagation",
    )
    assert creds["IdentityId"] == identity_id
    assert creds["Credentials"]["AccessKeyId"]
    assert creds["Credentials"]["SecretKey"]
    assert creds["Credentials"]["SessionToken"]

    federated_sts = _boto_client_with_creds(ctx, creds["Credentials"])
    caller = federated_sts.get_caller_identity()
    assert role_name in caller["Arn"], f"assumed identity arn {caller['Arn']} does not reference role {role_name}"
    assert ":assumed-role/" in caller["Arn"]


def _try_get_role_arn(iam, role_name: str) -> str | None:
    try:
        return iam.get_role(RoleName=role_name)["Role"]["Arn"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchEntity":
            return None
        raise


def _try_get_credentials(ci, identity_id: str) -> dict[str, Any] | None:
    try:
        return ci.get_credentials_for_identity(IdentityId=identity_id)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if code in ("InvalidIdentityPoolConfigurationException", "ExternalServiceException", "ResourceConflictException"):
            return None
        raise


def _boto_client_with_creds(ctx, creds: dict[str, str]):
    """A client on the target signed with the vended temporary credentials."""
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _poll_until(ctx, probe, predicate, *, timeout_s=30.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last observed: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
