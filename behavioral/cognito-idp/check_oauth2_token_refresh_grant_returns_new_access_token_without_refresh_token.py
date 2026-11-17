"""oauth2-token-refresh-grant-returns-new-access-token-without-refresh-token."""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "oauth2-token-refresh-grant-returns-new-access-token-without-refresh-token"
GROUP = "hosted-oauth2"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
# A fresh prefix domain is ACTIVE in seconds but its hostname answers only after minutes, so the
# wait polls the endpoint with a refused grant within the 1800 s budget declared here.
ENDPOINT_READY_TIMEOUT_S = 1380.0


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The /oauth2/token refresh grant without rotation answers 200 with access_token, id_token,
    expires_in 1800 and Bearer but no refresh_token, for the user and client; a garbage token, an
    unknown client and a missing token answer 400 invalid_grant, invalid_client and invalid_request."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-rtgrant-pool-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool(UserPoolId=pool_id),
                             "ResourceNotFoundException"))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-rtgrant-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        AccessTokenValidity=30, IdTokenValidity=45,
        TokenValidityUnits={"AccessToken": "minutes", "IdToken": "minutes"},
    )["UserPoolClient"]["ClientId"]
    domain = ctx.unique_name("sim2real-behav-rtgrant-")
    c.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id),
                             "ResourceNotFoundException", "InvalidParameterException"))
    base_url, route_headers = f"https://{domain}.auth.{ctx.region}.amazoncognito.com", {}
    token_url = f"{base_url}/oauth2/token"

    username = ctx.unique_name("sim2real-behav-rtgrant-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD,
                              Permanent=True)
    sub = next(a["Value"] for a in c.admin_get_user(UserPoolId=pool_id, Username=username)
               ["UserAttributes"] if a["Name"] == "sub")
    first = c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]

    # A garbage refresh token is refused; polling it doubles as the readiness wait.
    status, _, body = _poll_ready(token_url, route_headers, {"grant_type": "refresh_token",
                                              "client_id": client_id, "refresh_token": "garbage"})
    assert (status, _json(body)) == (400, {"error": "invalid_grant"}), (
        f"a garbage refresh token returned HTTP {status!r} {body[:200]!r}"
    )
    status, _, body = _post(token_url, route_headers, {"grant_type": "refresh_token", "client_id": "1" * 26,
                                        "refresh_token": first["RefreshToken"]})
    assert (status, _json(body)) == (400, {"error": "invalid_client"}), (
        f"an unknown client_id returned HTTP {status!r} {body[:200]!r}"
    )
    status, _, body = _post(token_url, route_headers, {"grant_type": "refresh_token", "client_id": client_id})
    assert (status, _json(body)) == (400, {"error": "invalid_request",
                                           "error_description": "invalid_refresh_token"}), (
        f"a refresh grant with no refresh_token returned HTTP {status!r} {body[:200]!r}"
    )

    status, headers, body = _post(token_url, route_headers, {"grant_type": "refresh_token", "client_id": client_id,
                                              "refresh_token": first["RefreshToken"]})
    assert status == 200, f"the refresh grant returned HTTP {status!r} {body[:200]!r}"
    assert headers.get("Content-Type") == "application/json;charset=UTF-8", (
        f"token response Content-Type was {headers.get('Content-Type')!r}"
    )
    grant = _json(body)
    assert sorted(grant) == ["access_token", "expires_in", "id_token", "token_type"], (
        f"refresh grant response members were {sorted(grant)!r}; no refresh_token is expected "
        "without rotation"
    )
    assert (grant["token_type"], grant["expires_in"]) == ("Bearer", 1800), (
        f"token_type/expires_in were {grant['token_type']!r}/{grant['expires_in']!r}, expected "
        "Bearer/1800 (AccessTokenValidity 30 minutes)"
    )

    access = _claims(grant["access_token"])
    assert (access["token_use"], access["client_id"], access["username"]) == (
        "access", client_id, username), (
        f"new access token token_use/client_id/username matched: "
        f"{access.get('token_use')!r}, {access.get('client_id') == client_id}, "
        f"{access.get('username') == username}"
    )
    assert access["sub"] == sub, "the new access token's sub is not the user's sub"
    assert access["exp"] - access["iat"] == 1800, (
        f"access token lifetime was {access['exp'] - access['iat']!r}s, expected 1800"
    )
    assert access["jti"] != _claims(first["AccessToken"])["jti"], (
        "the refresh grant returned the original access token instead of a new one"
    )
    ident = _claims(grant["id_token"])
    assert (ident["token_use"], ident["aud"], ident["sub"]) == ("id", client_id, sub), (
        f"new id token token_use was {ident.get('token_use')!r}; aud and sub matched: "
        f"{ident.get('aud') == client_id}, {ident.get('sub') == sub}"
    )
    assert ident["exp"] - ident["iat"] == 2700, (
        f"id token lifetime was {ident['exp'] - ident['iat']!r}s, expected 2700 (45 minutes)"
    )
    assert c.get_user(AccessToken=grant["access_token"])["Username"] == username, (
        "GetUser did not accept the access token the refresh grant minted"
    )


def _post(url: str, route_headers: dict, form: dict) -> tuple[int, dict, bytes]:
    req = urllib.request.Request(  # customer-built AWS host
        url, method="POST", data=urllib.parse.urlencode(form).encode(),
        headers={**route_headers, "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def _poll_ready(url: str, route_headers: dict, form: dict) -> tuple[int, dict, bytes]:
    """Poll a refused grant until the hosted domain answers with a 4xx a live endpoint gives.
    Transport errors (the name not yet resolvable) and 5xx warm-up answers retry."""
    deadline = time.monotonic() + ENDPOINT_READY_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            status, headers, body = _post(url, route_headers, form)
            last = (status, body[:200])
            if 400 <= status < 500:
                return status, headers, body
        except (urllib.error.URLError, OSError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        time.sleep(2)
    raise AssertionError(
        f"the hosted-domain token endpoint never answered within {ENDPOINT_READY_TIMEOUT_S:.0f}s; "
        f"last {last!r}"
    )


def _json(body: bytes) -> dict:
    try:
        return json.loads(body.decode() or "{}")
    except ValueError:
        return {"unparseable": body[:200].decode(errors="replace")}


def _claims(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
