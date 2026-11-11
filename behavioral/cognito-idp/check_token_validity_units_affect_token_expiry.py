"""token-validity-units-affect-token-expiry."""
from __future__ import annotations

import base64
import json

from behavioral_harness import tags

CHECK = "token-validity-units-affect-token-expiry"
GROUP = 'auth-state-machine'
SERVICES = ['cognito-idp']

PASSWORD = "Sup3r-Secret-Passw0rd!"
ADMIN_AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _decode_jwt_segment(segment: str) -> dict:
    """base64url-decode a JWT header/payload segment into a dict (no signature verify)."""
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A client with 5-minute access and 10-minute ID token validity issues tokens with ExpiresIn 300 and
    exp-iat of 300 and 600 seconds, and a default client issues 3600-second access tokens, as relying
    parties see token lifetime only this way."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    short_client = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(ADMIN_AUTH_FLOWS),
        GenerateSecret=False,
        AccessTokenValidity=5,
        IdTokenValidity=10,
        RefreshTokenValidity=1,
        TokenValidityUnits={
            "AccessToken": "minutes",
            "IdToken": "minutes",
            "RefreshToken": "days",
        },
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=short_client: c.delete_user_pool_client(
            UserPoolId=_p, ClientId=_c
        )
    )
    default_client = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(ADMIN_AUTH_FLOWS),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=default_client: c.delete_user_pool_client(
            UserPoolId=_p, ClientId=_c
        )
    )

    described = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=short_client)[
        "UserPoolClient"
    ]
    assert described.get("AccessTokenValidity") == 5, (
        f"DescribeUserPoolClient must round-trip AccessTokenValidity=5, got "
        f"{described.get('AccessTokenValidity')}"
    )
    assert described.get("TokenValidityUnits", {}).get("AccessToken") == "minutes", (
        f"DescribeUserPoolClient must round-trip TokenValidityUnits.AccessToken='minutes', "
        f"got {described.get('TokenValidityUnits')}"
    )

    username = ctx.unique_name("sim2real-behav-cipuser")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    def _authenticate(client_id: str) -> dict:
        return c.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )["AuthenticationResult"]

    short_result = _authenticate(short_client)
    assert short_result["ExpiresIn"] == 300, (
        f"AccessTokenValidity=5 minutes must surface as ExpiresIn=300, got "
        f"{short_result['ExpiresIn']} (an ExpiresIn of 3600 means the configured lifetime "
        f"was ignored)"
    )

    access_claims = _decode_jwt_segment(short_result["AccessToken"].split(".")[1])
    assert access_claims["exp"] - access_claims["iat"] == 300, (
        f"the AccessToken's own exp-iat must be 300s for AccessTokenValidity=5 minutes, got "
        f"{access_claims['exp'] - access_claims['iat']}"
    )
    id_claims = _decode_jwt_segment(short_result["IdToken"].split(".")[1])
    assert id_claims["exp"] - id_claims["iat"] == 600, (
        f"the IdToken's own exp-iat must be 600s for IdTokenValidity=10 minutes, got "
        f"{id_claims['exp'] - id_claims['iat']}"
    )
    assert access_claims["exp"] < id_claims["exp"], (
        f"a 5-minute access token must expire before a 10-minute id token; got "
        f"access exp={access_claims['exp']} id exp={id_claims['exp']}"
    )

    # --- control: an unconfigured client still gets the documented 1-hour default ---
    default_result = _authenticate(default_client)
    assert default_result["ExpiresIn"] == 3600, (
        f"a client with no validity configuration must default to ExpiresIn=3600, got "
        f"{default_result['ExpiresIn']}"
    )
    default_claims = _decode_jwt_segment(default_result["AccessToken"].split(".")[1])
    assert default_claims["exp"] - default_claims["iat"] == 3600, (
        f"the default AccessToken exp-iat must be 3600s, got "
        f"{default_claims['exp'] - default_claims['iat']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
