"""get-credentials-without-roles-configured-rejected."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "get-credentials-without-roles-configured-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity on a pool that never had SetIdentityPoolRoles is refused with
    InvalidIdentityPoolConfigurationException and the exact message; after the role is configured
    the identical call returns credentials."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    # No SetIdentityPoolRoles has been called yet: the pool has no role configuration at all.
    code, message = _refusal(lambda: ci.get_credentials_for_identity(IdentityId=identity_id))
    assert code == "InvalidIdentityPoolConfigurationException", f"got {code!r}: {message!r}"
    assert message == (
        "Invalid identity pool configuration. Check assigned IAM roles for this pool."
    ), message

    # Effect absent, via an independent read: the identity exists but nothing was ever vended.
    described = ci.describe_identity(IdentityId=identity_id)
    assert described["IdentityId"] == identity_id, described

    # Restore: configure the unauthenticated role the identity is entitled to.
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn})

    # The identical call now succeeds once IAM/STS trust propagates.
    creds = _poll_until_credentials(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_id),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert creds.get("Credentials", {}).get("AccessKeyId"), creds


def _refusal(fn: Any) -> tuple[str, str]:
    """Call fn(); return the refusal's (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected GetCredentialsForIdentity to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _poll_until_credentials(fn: Any, *, timeout_s: float, interval_s: float) -> dict:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code not in (
                "InvalidIdentityPoolConfigurationException",
                "NotAuthorizedException",
                "AccessDeniedException",
            ):
                raise
            time.sleep(interval_s)
    raise AssertionError(
        f"GetCredentialsForIdentity never succeeded within {timeout_s}s after roles were "
        f"configured (last error: {last_code!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
