"""get-credentials-for-identity-expiration-is-one-hour."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-credentials-for-identity-expiration-is-one-hour"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-identity"]

# Credentials from the enhanced authentication flow are valid for one hour.
_CREDENTIALS_TTL_S = 3600
# Client/server clock skew plus request latency, on each side of issuance + TTL.
_SKEW_S = 120


@tags("axis:happy-path", "cap:c4", "cap:c7", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity returns credentials whose Expiration is one hour after issuance
    (within 120 s either side), and sts:GetCallerIdentity accepts them as the pool's role.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html
    """
    cog = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_id = cog.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_cid_ttl1h_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _safe(lambda: cog.delete_identity_pool(IdentityPoolId=pool_id)))

    role_name = ctx.unique_name("sim2real-cid-ttl1h-role-")
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
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    cog.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn})

    identity_id = cog.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: _safe(lambda: cog.delete_identities(IdentityIdsToDelete=[identity_id])))

    creds, issued_at = _wait_for_credentials(cog, identity_id, timeout_s=60)
    lifetime_s = (creds["Expiration"] - issued_at).total_seconds()
    assert _CREDENTIALS_TTL_S - _SKEW_S <= lifetime_s <= _CREDENTIALS_TTL_S + _SKEW_S, (
        f"credentials expire {lifetime_s:.0f}s after issuance (Expiration {creds['Expiration']!r}), "
        f"expected {_CREDENTIALS_TTL_S}s within {_SKEW_S}s either side"
    )

    sts_temp = _sts_client_with_creds(ctx, creds)
    caller = sts_temp.get_caller_identity()
    assert role_name in caller["Arn"], (
        f"credentials resolve to {caller['Arn']!r}, expected the trusted role {role_name!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _wait_for_credentials(cog, identity_id: str, timeout_s: float = 60.0):
    """The identity's credentials and the instant just before the call that returned them."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        issued_at = datetime.now(timezone.utc)
        try:
            return cog.get_credentials_for_identity(IdentityId=identity_id)["Credentials"], issued_at
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] not in (
                "InvalidIdentityPoolConfigurationException",
                "NotAuthorizedException",
            ):
                raise
            time.sleep(3)
    raise AssertionError(f"credentials never became available: {last_err}")


def _sts_client_with_creds(ctx, creds: dict):
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
