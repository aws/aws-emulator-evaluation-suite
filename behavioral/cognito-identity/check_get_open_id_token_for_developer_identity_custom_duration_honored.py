"""get-open-id-token-for-developer-identity-custom-duration-honored."""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-open-id-token-for-developer-identity-custom-duration-honored"
GROUP = "data-plane"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetOpenIdTokenForDeveloperIdentity with a custom TokenDuration issues a JWT whose exp-iat
    equals that duration, and GetCredentialsForIdentity redeems the token for STS credentials with a
    future Expiration."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    dev_provider_name = ctx.unique_name("sim2real-dev-").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=dev_provider_name,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-cid-custdur-role-")
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
            },
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"authenticated": role_arn})

    dev_user_id = ctx.unique_name("dev-user-")
    custom_duration_s = 3600  # 1 hour; default (unspecified) is 900s (15 min)

    resp = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        Logins={dev_provider_name: dev_user_id},
        TokenDuration=custom_duration_s,
    )
    identity_id = resp["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))
    token = resp["Token"]

    payload = _decode_jwt_payload(token)
    assert "iat" in payload and "exp" in payload, f"JWT payload missing iat/exp: {payload!r}"
    delta = payload["exp"] - payload["iat"]
    assert delta == custom_duration_s, (
        f"exp-iat delta {delta}s does not match requested TokenDuration {custom_duration_s}s"
    )

    # Redeem the token for STS credentials through GetCredentialsForIdentity, so the token is
    # proven usable downstream, not only well-formed.
    creds = _wait_for_credentials(
        ci, identity_id, {"cognito-identity.amazonaws.com": token}, timeout_s=60.0,
    )
    assert creds.get("AccessKeyId") and creds.get("SecretKey") and creds.get("SessionToken"), (
        f"GetCredentialsForIdentity did not redeem the custom-duration token for a full "
        f"credential envelope: {sorted(creds)}"
    )
    assert creds["Expiration"] > datetime.now(timezone.utc), (
        f"credential Expiration {creds['Expiration']} from redeeming the custom-duration token "
        f"is not in the future"
    )


def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    assert len(parts) == 3, f"malformed JWT (expected 3 dot-separated parts): {token!r}"
    payload_segment = parts[1]
    padding = "=" * (-len(payload_segment) % 4)
    raw = base64.urlsafe_b64decode(payload_segment + padding)
    return json.loads(raw)


def _wait_for_credentials(ci, identity_id: str, logins: dict, timeout_s: float = 60.0) -> dict:
    """GetCredentialsForIdentity can transiently fail right after SetIdentityPoolRoles due to
    IAM trust-policy propagation delay; poll until it succeeds or the timeout is exhausted."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ci.get_credentials_for_identity(IdentityId=identity_id, Logins=logins)["Credentials"]
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] not in (
                "InvalidIdentityPoolConfigurationException",
                "NotAuthorizedException",
            ):
                raise
            time.sleep(3)
    raise AssertionError(f"credentials for the custom-duration token never became available: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
