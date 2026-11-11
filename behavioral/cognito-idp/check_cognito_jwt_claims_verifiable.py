"""cognito-jwt-claims-verifiable."""
from __future__ import annotations

import base64
import json

from behavioral_harness import tags

PASSWORD = "Sup3r-Secret-Passw0rd!"

CHECK = "cognito-jwt-claims-verifiable"
GROUP = 'auth-state-machine'
SERVICES = ['cognito-idp']

def _decode_jwt_segment(segment: str) -> dict:
    """base64url-decode a JWT header/payload segment into a dict (no signature verify)."""
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))

ADMIN_AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

ADMIN_AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The IdToken and AccessToken are RS256 JWTs with a kid, an iss naming the pool and exp > iat;
    the IdToken aud and AccessToken client_id name the app client, and GetUser with the AccessToken
    returns the user."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(ADMIN_AUTH_FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    result = c.admin_initiate_auth(UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH", AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD})["AuthenticationResult"]
    id_token = result["IdToken"]
    access_token = result["AccessToken"]

    for label, token in (("IdToken", id_token), ("AccessToken", access_token)):
        parts = token.split(".")
        assert len(parts) == 3, f"{label} is not a well-formed JWT (header.payload.signature)"

        header = _decode_jwt_segment(parts[0])
        assert header.get("kid"), f"{label} header missing kid: {header}"
        assert header.get("alg") == "RS256", f"{label} header alg expected RS256, got {header.get('alg')}"

        payload = _decode_jwt_segment(parts[1])
        assert pool_id in payload.get("iss", ""), (
            f"{label} iss should contain the pool id {pool_id}, got {payload.get('iss')}"
        )
        assert payload.get("token_use"), f"{label} payload missing token_use: {payload}"
        assert payload["exp"] > payload["iat"], (
            f"{label} exp ({payload.get('exp')}) must be after iat ({payload.get('iat')})"
        )

    id_payload = _decode_jwt_segment(id_token.split(".")[1])
    assert id_payload.get("aud") == client_id, (
        f"IdToken aud must match the app client {client_id}, got {id_payload.get('aud')}"
    )
    assert id_payload.get("token_use") == "id", (
        f"expected IdToken token_use 'id', got {id_payload.get('token_use')}"
    )

    access_payload = _decode_jwt_segment(access_token.split(".")[1])
    assert access_payload.get("client_id") == client_id, (
        f"AccessToken client_id must match the app client {client_id}, got {access_payload.get('client_id')}"
    )
    assert access_payload.get("token_use") == "access", (
        f"expected AccessToken token_use 'access', got {access_payload.get('token_use')}"
    )

    got_user = c.get_user(AccessToken=access_token)
    assert got_user["Username"] == username, (
        f"get_user via the AccessToken should resolve to {username}, got {got_user.get('Username')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
