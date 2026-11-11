"""deep-cognito-idp-3-enforce-app-client-read-attrs-withheld."""
from __future__ import annotations

import base64
import json
import secrets

from behavioral_harness import tags

CHECK = "deep-cognito-idp-3-enforce-app-client-read-attrs-withheld"
GROUP = "authorization"
SERVICES = ["cognito-idp"]


@tags(
    "axis:happy-path",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """With ReadAttributes=["email"], GetUser and the ID token through the client omit name and keep
    email, while a twin client without attribute permissions returns name for the same user."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-rattr-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
    restricted = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-rattr-r-"),
        ExplicitAuthFlows=flows,
        ReadAttributes=["email"],
    )["UserPoolClient"]["ClientId"]
    twin = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-rattr-d-"),
        ExplicitAuthFlows=flows,
    )["UserPoolClient"]["ClientId"]

    r_desc = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=restricted)["UserPoolClient"]
    assert r_desc.get("ReadAttributes") == ["email"], (
        f"restricted client should persist ReadAttributes=['email'], got {r_desc.get('ReadAttributes')!r}"
    )

    username = ctx.unique_name("sim2real-behav-rattr-u-")
    full_name = "Ada Restricted Lovelace"
    password = _strong_password()
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=_strong_password(),
        UserAttributes=[
            {"Name": "email", "Value": "rattr@example.com"},
            {"Name": "name", "Value": full_name},
        ],
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    admin_attrs = _attrs(idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"])
    assert admin_attrs.get("name") == full_name, (
        f"AdminGetUser must prove `name` is set before the read test means anything; got {admin_attrs!r}"
    )

    r_tokens = _sign_in(idp, restricted, username, password)
    t_tokens = _sign_in(idp, twin, username, password)

    r_user = _attrs(idp.get_user(AccessToken=r_tokens["AccessToken"])["UserAttributes"])
    t_user = _attrs(idp.get_user(AccessToken=t_tokens["AccessToken"])["UserAttributes"])

    assert "name" not in r_user, (
        f"GetUser through the ReadAttributes=['email'] client leaked `name`: {r_user!r}"
    )
    assert r_user.get("email") == "rattr@example.com", (
        f"GetUser through the restricted client must still return the readable `email`, got {r_user!r}"
    )
    assert t_user.get("name") == full_name, (
        f"twin client (default permissions) GetUser must return `name`={full_name!r}, got {t_user!r}"
    )

    r_claims = _jwt_claims(r_tokens["IdToken"])
    t_claims = _jwt_claims(t_tokens["IdToken"])
    assert "name" not in r_claims, (
        f"restricted client's ID token carries the unreadable `name` claim: {sorted(r_claims)!r}"
    )
    assert r_claims.get("email") == "rattr@example.com", (
        f"restricted client's ID token must still carry `email`, got claims {sorted(r_claims)!r}"
    )
    assert t_claims.get("name") == full_name, (
        f"twin client's ID token must carry `name`={full_name!r}, got {t_claims.get('name')!r}"
    )
    assert r_claims.get("sub") == t_claims.get("sub") == admin_attrs.get("sub"), (
        f"both tokens must name the same user: restricted sub={r_claims.get('sub')!r} "
        f"twin sub={t_claims.get('sub')!r} admin sub={admin_attrs.get('sub')!r}"
    )


def _strong_password() -> str:
    # Random per run so the advanced-security compromised-credential list can never match it.
    return "Aa1!" + secrets.token_urlsafe(18)


def _attrs(items) -> dict:
    return {a["Name"]: a["Value"] for a in items}


def _sign_in(idp, client_id: str, username: str, password: str) -> dict:
    resp = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in resp, f"expected tokens from USER_PASSWORD_AUTH, got {resp!r}"
    return resp["AuthenticationResult"]


def _jwt_claims(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
