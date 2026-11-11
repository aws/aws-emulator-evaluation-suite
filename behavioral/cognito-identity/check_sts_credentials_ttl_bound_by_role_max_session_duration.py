"""sts-credentials-ttl-bound-by-role-max-session-duration."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "sts-credentials-ttl-bound-by-role-max-session-duration"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity vends a ~1 hour session even when the role's MaxSessionDuration
    allows 12 hours: the fixed default STS session duration applies, not the role's allowance."""
    cid = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    pool = cid.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))

    role_name, role_arn = _create_trusting_role(ctx, pool_id, "unauthenticated", max_session_duration=43200)
    cid.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn})

    identity_id = cid.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: cid.delete_identities(IdentityIdsToDelete=[identity_id]))

    creds = _get_credentials_with_retry(ctx, identity_id)["Credentials"]
    role = iam.get_role(RoleName=role_name)["Role"]
    max_session_duration = role["MaxSessionDuration"]
    assert max_session_duration == 43200, (
        f"expected the role's stored MaxSessionDuration to be the 43200s we set, got {max_session_duration}"
    )

    now = datetime.now(timezone.utc)
    ttl_s = (creds["Expiration"] - now).total_seconds()
    assert 0 < ttl_s < max_session_duration, (
        f"expected TTL well under the {max_session_duration}s role ceiling, got {ttl_s}s"
    )
    assert 1800 <= ttl_s <= 4200, (
        f"expected the actual session to sit near the ~3600s default, not the 12h role "
        f"allowance, got {ttl_s}s"
    )

    sts_temp = _sts_client_with_creds(ctx, creds)
    caller = sts_temp.get_caller_identity()
    assert role_name in caller["Arn"], (
        f"expected the vended credentials' caller identity to reflect role {role_name!r}, "
        f"got {caller['Arn']!r}"
    )


def _create_trusting_role(ctx, pool_id: str, amr: str, max_session_duration: int = 3600):
    import json

    iam = ctx.client("iam")
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
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
                },
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        MaxSessionDuration=max_session_duration,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_name, role["Arn"]


def _sts_client_with_creds(ctx, creds: dict):
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _get_credentials_with_retry(
    ctx, identity_id, logins=None, custom_role_arn=None, timeout_s=45.0, interval_s=3.0
):
    import time

    from botocore.exceptions import ClientError

    cid = ctx.client("cognito-identity")
    kwargs = {"IdentityId": identity_id}
    if logins:
        kwargs["Logins"] = logins
    if custom_role_arn:
        kwargs["CustomRoleArn"] = custom_role_arn
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cid.get_credentials_for_identity(**kwargs)
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"GetCredentialsForIdentity never succeeded within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
