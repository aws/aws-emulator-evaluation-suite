"""access-token-ttl-matches-pool-config."""
from __future__ import annotations

import base64
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-token-ttl-matches-pool-config"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Tokens issued by InitiateAuth and AdminInitiateAuth carry an exp claim
    consistent with the app client's configured AccessTokenValidity (5 minutes, the
    minimum allowed), for both the user-initiated and admin-initiated auth paths."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-"),
        UserPoolTags={"sim2real:managed": "true"},
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    configured_seconds = 5 * 60
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        ],
        AccessTokenValidity=5,
        TokenValidityUnits={"AccessToken": "minutes"},
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: _ignore(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)))

    described = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert described["AccessTokenValidity"] == 5, (
        f"DescribeUserPoolClient must round-trip AccessTokenValidity=5, got {described['AccessTokenValidity']}"
    )
    assert described["TokenValidityUnits"]["AccessToken"] == "minutes", (
        f"DescribeUserPoolClient must round-trip TokenValidityUnits.AccessToken='minutes', "
        f"got {described['TokenValidityUnits']}"
    )

    username, password = _create_confirmed_user(ctx, pool_id)

    auth = idp.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert auth["AuthenticationResult"]["ExpiresIn"] == configured_seconds, (
        f"InitiateAuth ExpiresIn must equal the configured {configured_seconds}s, "
        f"got {auth['AuthenticationResult']['ExpiresIn']}"
    )
    claims = _decode_jwt_payload(auth["AuthenticationResult"]["AccessToken"])
    assert claims["token_use"] == "access", f"expected token_use='access', got {claims.get('token_use')}"
    ttl = claims["exp"] - claims["iat"]
    assert ttl == configured_seconds, (
        f"InitiateAuth access token TTL must be exactly {configured_seconds}s, got {ttl}s"
    )

    admin_auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert admin_auth["AuthenticationResult"]["ExpiresIn"] == configured_seconds, (
        f"AdminInitiateAuth ExpiresIn must equal the configured {configured_seconds}s, "
        f"got {admin_auth['AuthenticationResult']['ExpiresIn']}"
    )
    admin_claims = _decode_jwt_payload(admin_auth["AuthenticationResult"]["AccessToken"])
    assert admin_claims["token_use"] == "access", (
        f"expected token_use='access', got {admin_claims.get('token_use')}"
    )
    admin_ttl = admin_claims["exp"] - admin_claims["iat"]
    assert admin_ttl == configured_seconds, (
        f"AdminInitiateAuth access token TTL must be exactly {configured_seconds}s, got {admin_ttl}s"
    )


def _decode_jwt_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _create_confirmed_user(ctx, pool_id):
    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Passw0rd"
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username,
        TemporaryPassword="Temp0rary!Passw0rd", MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: _ignore(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username)))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
