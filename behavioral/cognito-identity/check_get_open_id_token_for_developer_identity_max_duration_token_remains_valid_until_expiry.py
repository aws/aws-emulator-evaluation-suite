"""get-open-id-token-for-developer-identity-max-duration-token-remains-valid-until-expiry."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-max-duration-token-remains-valid-until-expiry"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-identity"]


# timing:real-time — ttl: 1 s https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetOpenIdTokenForDeveloperIdentity.html
@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control",
      "timing:real-time")
def run(ctx) -> None:
    """A developer-identity OpenId token issued with TokenDuration=86400 (max) is usable for
    credential exchange immediately, while one issued with TokenDuration=1 (min) stops being
    accepted once its 1-second expiry has elapsed -- pinning both ends of the validity window."""
    cog = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    dev_provider = "sim2real.devttl." + ctx.unique_name("p").replace("_", "-")
    pool_id = cog.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_cid_devttl_"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _safe(lambda: cog.delete_identity_pool(IdentityPoolId=pool_id)))

    role_name = ctx.unique_name("sim2real-cid-devttl-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    cog.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"authenticated": role_arn})

    user_id = ctx.unique_name("dev-user-")

    # --- max duration token: must be usable now ---
    max_resp = cog.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_id}, TokenDuration=86400
    )
    identity_id = max_resp["IdentityId"]
    ctx.on_cleanup(lambda: _safe(lambda: cog.delete_identities(IdentityIdsToDelete=[identity_id])))
    max_token = max_resp["Token"]

    creds = _wait_for_credentials(
        cog, identity_id, {"cognito-identity.amazonaws.com": max_token}, timeout_s=60
    )
    assert creds["AccessKeyId"] and creds["SecretKey"] and creds["SessionToken"], (
        f"max-duration token: GetCredentialsForIdentity returned an incomplete credential set: {creds}"
    )
    assert creds["Expiration"] > datetime.now(timezone.utc), (
        f"max-duration token: expected Expiration in the future, got {creds['Expiration']}"
    )

    sts_temp = _sts_client_with_creds(ctx, creds)
    caller = sts_temp.get_caller_identity()
    assert role_name in caller["Arn"] and "assumed-role" in caller["Arn"], (
        f"expected an assumed-role identity for {role_name}, got {caller['Arn']}"
    )

    # --- min duration (1s) token: immediately usable, same identity re-issued ---
    min_resp = cog.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={dev_provider: user_id}, TokenDuration=1
    )
    assert min_resp["IdentityId"] == identity_id, (
        f"expected the min-duration token to re-issue the same developer identity "
        f"{identity_id}, got {min_resp['IdentityId']}"
    )
    min_token = min_resp["Token"]

    min_creds = cog.get_credentials_for_identity(
        IdentityId=identity_id, Logins={"cognito-identity.amazonaws.com": min_token}
    )["Credentials"]
    assert min_creds["AccessKeyId"] and min_creds["SecretKey"] and min_creds["SessionToken"], (
        f"min-duration token: GetCredentialsForIdentity returned an incomplete credential set "
        f"before expiry: {min_creds}"
    )

    # AWS documents a clock-skew grace period of "usually no more than 5 minutes" layered on
    # top of the nominal TokenDuration, so proving that a 1s-duration token eventually gets
    # rejected requires waiting well past that documented window: the poll below runs for up
    # to 450 s and exits as soon as the expired token is rejected.
    deadline = time.monotonic() + 450  # nominal 1s + generous grace-period buffer
    refusal = None
    while time.monotonic() < deadline:
        try:
            cog.get_credentials_for_identity(
                IdentityId=identity_id, Logins={"cognito-identity.amazonaws.com": min_token}
            )
        except ClientError as e:
            refusal = (e.response["Error"]["Code"], e.response["Error"].get("Message"))
            break
        time.sleep(15)
    if refusal is None:
        raise AssertionError("min-duration token still accepted past its expiry + grace-period buffer")
    code, message = refusal
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException for the expired min-duration token, got {code}: {message!r}"
    )
    expected = "Invalid login token. Token is expired."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====

def _safe(fn) -> None:
    """Run a teardown call; tolerate only the resource already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _wait_for_credentials(cog, identity_id: str, logins: dict, timeout_s: float = 60.0):
    """GetCredentialsForIdentity can transiently fail right after SetIdentityPoolRoles due to
    IAM trust-policy propagation delay; poll until it succeeds or the timeout is exhausted."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cog.get_credentials_for_identity(IdentityId=identity_id, Logins=logins)[
                "Credentials"
            ]
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
