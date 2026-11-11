"""e2e-credentials-for-identity-without-roles-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-credentials-for-identity-without-roles-rejected"
GROUP = "e2e"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c7", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity is rejected before roles are configured; succeeds once they are."""
    cog = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool = cog.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-norole-pool-"),
        AllowUnauthenticatedIdentities=True,
    )
    pool_id = pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: cog.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = cog.get_id(IdentityPoolId=pool_id)["IdentityId"]

    # No SetIdentityPoolRoles has been called for this fresh pool yet.
    err = _client_error(lambda: cog.get_credentials_for_identity(IdentityId=identity_id))
    assert err == ("InvalidIdentityPoolConfigurationException", "Invalid identity pool configuration. Check assigned IAM roles for this pool."), err

    # Effect absent: no credentials were minted for this identity.
    describe = cog.describe_identity(IdentityId=identity_id)
    assert describe["IdentityId"] == identity_id, describe  # identity exists but is still credential-less

    # Positive control: configure the unauthenticated role, then the very same identity
    # succeeds in obtaining real STS credentials.
    role_name = ctx.unique_name("sim2real-norole-role-")
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
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "get-caller-identity"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    cog.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn})

    creds = _poll_until_success(
        lambda: cog.get_credentials_for_identity(IdentityId=identity_id),
        retryable_codes={"NotAuthorizedException", "InvalidIdentityPoolConfigurationException"},
        timeout_s=90.0,
        interval_s=3.0,
    )["Credentials"]

    sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    caller = sts.get_caller_identity()
    assert f"assumed-role/{role_name}/" in caller["Arn"], caller["Arn"]


def _client_error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until_success(fn, *, retryable_codes, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in retryable_codes:
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"never succeeded within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
