"""get-tokens-from-refresh-token-preserves-original-scopes."""
from __future__ import annotations

import base64
import json

from behavioral_harness import tags

CHECK = "get-tokens-from-refresh-token-preserves-original-scopes"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTokensFromRefreshToken returns a freshly issued access token whose
    sub/client_id/scope claims match the original authentication exactly, and
    which GetUser (an independent read, at the destination) actually honours."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(ctx, pool_id)
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Passw0rd"
    _create_confirmed_user(ctx, pool_id, username, password)

    original = _admin_password_auth(ctx, pool_id, client_id, username, password)
    original_payload = _decode_jwt_payload(original["AccessToken"])

    refreshed = idp.get_tokens_from_refresh_token(RefreshToken=original["RefreshToken"], ClientId=client_id)
    refreshed_access_token = refreshed["AuthenticationResult"]["AccessToken"]
    refreshed_payload = _decode_jwt_payload(refreshed_access_token)

    assert refreshed_access_token != original["AccessToken"], (
        f"expected a freshly issued access token, got the original back unchanged: {refreshed_access_token!r}"
    )
    assert refreshed_payload["token_use"] == "access", (
        f"expected token_use 'access', got {refreshed_payload.get('token_use')!r}"
    )
    assert refreshed_payload["sub"] == original_payload["sub"], (
        f"expected sub {original_payload['sub']!r} preserved on refresh, got {refreshed_payload.get('sub')!r}"
    )
    assert refreshed_payload["client_id"] == original_payload["client_id"], (
        f"expected client_id {original_payload['client_id']!r} preserved on refresh, got {refreshed_payload.get('client_id')!r}"
    )
    assert refreshed_payload["scope"] == original_payload["scope"], (
        f"expected scope {original_payload['scope']!r} preserved on refresh, got {refreshed_payload.get('scope')!r}"
    )

    # Independent read at the destination: GetUser is a different operation than the
    # one under test, and proves the refreshed AccessToken is genuinely usable, not
    # just a JWT whose unverified claims happen to look right.
    whoami = idp.get_user(AccessToken=refreshed_access_token)
    assert whoami["Username"] == username, (
        f"expected GetUser with the refreshed access token to resolve to {username!r}, got {whoami.get('Username')!r}"
    )


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    kwargs.setdefault("UserPoolTags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real-"})
    resp = idp.create_user_pool(PoolName=name, **kwargs)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-client-")
    kwargs.setdefault("ExplicitAuthFlows", ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])
    resp = idp.create_user_pool_client(UserPoolId=pool_id, ClientName=name, GenerateSecret=False, **kwargs)
    return resp["UserPoolClient"]["ClientId"]


def _create_confirmed_user(ctx, pool_id, username, password, user_attributes=None):
    idp = ctx.client("cognito-idp")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
        UserAttributes=user_attributes or [],
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _admin_password_auth(ctx, pool_id, client_id, username, password):
    idp = ctx.client("cognito-idp")
    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]


def _decode_jwt_payload(token):
    payload_segment = token.split(".")[1]
    padded = payload_segment + "=" * (-len(payload_segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
