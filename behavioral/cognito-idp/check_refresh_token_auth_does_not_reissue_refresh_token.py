"""refresh-token-auth-does-not-reissue-refresh-token."""
from __future__ import annotations

import base64
import json

from behavioral_harness import tags

CHECK = "refresh-token-auth-does-not-reissue-refresh-token"
GROUP = 'refresh-token'
SERVICES = ['cognito-idp']

PASSWORD = "Sup3r-Secret-Passw0rd!"
USER_AUTH_FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _decode_jwt_segment(segment: str) -> dict:
    """base64url-decode a JWT header/payload segment into a dict (no signature verify)."""
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """REFRESH_TOKEN_AUTH returns new Bearer access and ID tokens for the same user and client but no
    RefreshToken, and the original refresh token works again, as clients cache it on that basis."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(USER_AUTH_FLOWS),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )
    username = ctx.unique_name("sim2real-behav-cipuser")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    original = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]
    refresh_token = original["RefreshToken"]
    original_access_claims = _decode_jwt_segment(original["AccessToken"].split(".")[1])

    def _refresh() -> dict:
        resp = c.initiate_auth(
            ClientId=client_id,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_token},
        )
        assert "ChallengeName" not in resp, (
            f"REFRESH_TOKEN_AUTH must not raise a challenge, got {resp.get('ChallengeName')}"
        )
        return resp["AuthenticationResult"]

    refreshed = _refresh()

    assert "RefreshToken" not in refreshed, (
        "REFRESH_TOKEN_AUTH must NOT reissue a RefreshToken (refresh-token rotation is off "
        f"by default); AuthenticationResult keys were {sorted(refreshed)}"
    )
    assert refreshed.get("AccessToken"), "expected a new AccessToken from REFRESH_TOKEN_AUTH"
    assert refreshed.get("IdToken"), "expected a new IdToken from REFRESH_TOKEN_AUTH"
    assert refreshed.get("TokenType") == "Bearer", (
        f"expected TokenType 'Bearer', got {refreshed.get('TokenType')}"
    )
    assert refreshed["AccessToken"] != original["AccessToken"], (
        "REFRESH_TOKEN_AUTH must mint a genuinely new AccessToken, not replay the old one"
    )

    refreshed_access_claims = _decode_jwt_segment(refreshed["AccessToken"].split(".")[1])
    assert refreshed_access_claims["sub"] == original_access_claims["sub"], (
        f"the refreshed AccessToken must keep the same sub; "
        f"{refreshed_access_claims['sub']} != {original_access_claims['sub']}"
    )
    assert refreshed_access_claims["token_use"] == "access", (
        f"expected token_use 'access', got {refreshed_access_claims['token_use']}"
    )
    assert refreshed_access_claims["client_id"] == client_id, (
        f"the refreshed AccessToken client_id must be {client_id}, got "
        f"{refreshed_access_claims['client_id']}"
    )
    assert original_access_claims.get("jti"), (
        f"the original AccessToken must carry a jti claim, got {sorted(original_access_claims)}"
    )
    assert refreshed_access_claims.get("jti") != original_access_claims.get("jti"), (
        "each issued AccessToken must carry its own jti; the refreshed token reused "
        f"{original_access_claims.get('jti')}"
    )

    refreshed_id_claims = _decode_jwt_segment(refreshed["IdToken"].split(".")[1])
    assert refreshed_id_claims["token_use"] == "id", (
        f"expected the refreshed IdToken token_use 'id', got {refreshed_id_claims['token_use']}"
    )
    assert refreshed_id_claims["aud"] == client_id, (
        f"the refreshed IdToken aud must be {client_id}, got {refreshed_id_claims['aud']}"
    )

    # --- control: without rotation the SAME refresh token is still usable ---
    second = _refresh()
    assert "RefreshToken" not in second, (
        f"the second refresh must also omit RefreshToken; keys were {sorted(second)}"
    )
    assert second.get("AccessToken"), (
        "a refresh token must remain reusable when rotation is not enabled — the second "
        "REFRESH_TOKEN_AUTH returned no AccessToken"
    )
    assert second["AccessToken"] != refreshed["AccessToken"], (
        "the second refresh must mint a distinct AccessToken"
    )

    # --- terminal read: an independent operation, not the minting call's own response ---
    me = c.get_user(AccessToken=second["AccessToken"])
    assert me["Username"] == username, (
        f"the second refreshed AccessToken must authenticate as {username} via an "
        f"independent GetUser call, got {me['Username']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
