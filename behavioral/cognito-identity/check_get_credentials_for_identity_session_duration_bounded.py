"""get-credentials-for-identity-session-duration-bounded."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-credentials-for-identity-session-duration-bounded"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity issues credentials whose Expiration is bounded to ~1 hour, and
    the credentials are usable: an independent sts:GetCallerIdentity call signed with them works."""
    client = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_id = _create_pool(ctx, client)
    role_name, role_arn = _create_unauth_role(ctx, iam, pool_id)
    client.set_identity_pool_roles(
        IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn, "authenticated": role_arn}
    )
    identity_id = client.get_id(IdentityPoolId=pool_id)["IdentityId"]

    creds = None
    last_err = None
    deadline = time.monotonic() + 60.0
    while creds is None and time.monotonic() < deadline:
        try:
            creds = client.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
        except ClientError as err:
            last_err = err.response["Error"]["Code"]
            time.sleep(3.0)
    assert creds is not None, f"GetCredentialsForIdentity never succeeded (last error: {last_err})"

    expiration = creds["Expiration"]
    now = datetime.now(timezone.utc)
    delta = (expiration - now).total_seconds()

    assert delta > 0, f"credentials Expiration is already in the past: {expiration}"
    assert delta >= 600, f"credentials session duration {delta:.0f}s is unexpectedly short"
    assert delta <= 3600 + 300, (
        f"credentials session duration {delta:.0f}s exceeds the ~1 hour max session bound"
    )

    sts_temp = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    caller_arn = sts_temp.get_caller_identity()["Arn"]
    assert role_name in caller_arn, (
        f"credentials with a plausible Expiration did not actually assume {role_name}: {caller_arn}"
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


def _create_unauth_role(ctx, iam_client, pool_id: str) -> tuple[str, str]:
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
    return role_name, role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
