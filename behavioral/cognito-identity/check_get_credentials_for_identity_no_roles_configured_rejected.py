"""get-credentials-for-identity-no-roles-configured-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-credentials-for-identity-no-roles-configured-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity refuses to issue credentials for a pool with no IAM roles set."""
    client = ctx.client("cognito-identity")
    pool_id = _create_pool(ctx, client)  # SetIdentityPoolRoles is deliberately never called
    identity_id = client.get_id(IdentityPoolId=pool_id)["IdentityId"]

    err = _client_error(lambda: client.get_credentials_for_identity(IdentityId=identity_id))
    assert err == (
        "InvalidIdentityPoolConfigurationException",
        "Invalid identity pool configuration. Check assigned IAM roles for this pool.",
    ), f"expected InvalidIdentityPoolConfigurationException for a pool with no roles, got {err!r}"

    # positive control: configuring a role for the exact same identity permits credentials
    iam = ctx.client("iam")
    role_arn = _create_unauth_role(ctx, iam, pool_id)
    client.set_identity_pool_roles(
        IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn, "authenticated": role_arn}
    )

    creds = None
    last_err = None
    deadline = time.monotonic() + 60.0
    while creds is None and time.monotonic() < deadline:
        try:
            creds = client.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
        except ClientError as err:
            last_err = err.response["Error"]["Code"]
            time.sleep(3.0)
    assert creds is not None, (
        f"expected GetCredentialsForIdentity to succeed once roles were configured (last error: {last_err})"
    )


def _create_pool(ctx, client, **extra_fields: Any) -> str:
    params = {
        "IdentityPoolName": ctx.unique_name("sim2real-idp-"),
        "AllowUnauthenticatedIdentities": True,
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
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam_client.delete_role(RoleName=role_name))
    return role_arn


def _client_error(fn):
    """Call fn(); return the ClientError's (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
