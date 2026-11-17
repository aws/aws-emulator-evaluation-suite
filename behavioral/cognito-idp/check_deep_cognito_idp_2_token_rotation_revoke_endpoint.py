"""deep-cognito-idp-2-token-rotation-revoke-endpoint."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-idp-2-token-rotation-revoke-endpoint"
GROUP = "refresh-token-rotation"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
# A new prefix domain reports ACTIVE within seconds but its hostname takes minutes (about 5-10)
# to answer HTTP; the wait polls the endpoint itself with a refused revoke.
ENDPOINT_READY_TIMEOUT_S = 1380.0


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """POST /oauth2/revoke from the wrong client answers 401 invalid_client and revokes nothing;
    revoking the original rotated-out token makes GetTokensFromRefreshToken and GetUser refuse its
    family with NotAuthorizedException, while a new sign-in still works."""
    c = ctx.client("cognito-idp")

    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-rot-pool-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    clients = {}
    for grace in (0, 60):
        cid = c.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=ctx.unique_name(f"sim2real-behav-rot-g{grace}-"),
            ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"],
            RefreshTokenRotation={"Feature": "ENABLED", "RetryGracePeriodSeconds": grace},
        )["UserPoolClient"]["ClientId"]
        ctx.on_cleanup(lambda _c=cid: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=_c))
        clients[grace] = cid
    client_id, other_client_id = clients[0], clients[60]
    revocation = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert revocation.get("EnableTokenRevocation") is True, (
        f"client EnableTokenRevocation={revocation.get('EnableTokenRevocation')!r}, expected True by default"
    )

    domain = ctx.unique_name("sim2real-behav-rot-")
    c.create_user_pool_domain(UserPoolId=pool_id, Domain=domain)
    ctx.on_cleanup(lambda: c.delete_user_pool_domain(UserPoolId=pool_id, Domain=domain))
    base_url, route_headers = f"https://{domain}.auth.{ctx.region}.amazoncognito.com", {}
    revoke_url = f"{base_url}/oauth2/revoke"

    username = ctx.unique_name("sim2real-behav-rot-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    rt0 = _sign_in(c, client_id, username)
    rotated = c.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=rt0)["AuthenticationResult"]
    rt1, at1 = rotated["RefreshToken"], rotated["AccessToken"]
    assert rt1 != rt0, "rotation returned the same refresh token it was given"

    # Wrong client: refused at the endpoint. Polling it doubles as the readiness wait.
    status, body = _poll_endpoint(revoke_url, route_headers, rt0, other_client_id)
    assert status == 401, f"revoke by the wrong app client returned HTTP {status!r}: {body!r}"
    assert _json(body).get("error") == "invalid_client", f"wrong-client revoke body was {body!r}"
    assert c.get_user(AccessToken=at1)["Username"] == username, (
        "a refused wrong-client revoke must not revoke anything, but the family's access token stopped working"
    )

    # The act: revoke the ORIGINAL (already rotated-out) token at the hosted-UI endpoint.
    status, body = _post_revoke(revoke_url, route_headers, rt0, client_id)
    assert status == 200, f"POST /oauth2/revoke returned HTTP {status!r}: {body!r}"
    assert body == b"", f"successful revoke returned a body: {body!r}"

    # The terminal read at a different surface: the signed API refuses the derived tokens.
    code, message = _error(lambda: c.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=rt1))
    assert code == "NotAuthorizedException", (
        f"GetTokensFromRefreshToken with a token derived from the revoked family returned {code!r} ({message!r})"
    )
    ucode, umessage = _error(lambda: c.get_user(AccessToken=at1))
    assert ucode == "NotAuthorizedException", (
        f"GetUser with the family's access token after revoke returned {ucode!r} ({umessage!r})"
    )
    assert umessage == "Access Token has been revoked", f"GetUser revoke message was {umessage!r}"

    # Positive control: revocation is scoped to the family, not the user or client.
    fresh = c.get_tokens_from_refresh_token(
        ClientId=client_id, RefreshToken=_sign_in(c, client_id, username))["AuthenticationResult"]
    assert fresh.get("RefreshToken"), f"an unrelated sign-in on the same client could not refresh: {sorted(fresh)!r}"
    assert c.get_user(AccessToken=fresh["AccessToken"])["Username"] == username, "unrelated family's access token refused"


def _sign_in(c, client_id: str, username: str) -> str:
    return c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["RefreshToken"]


def _post_revoke(url: str, route_headers: dict, token: str, client_id: str) -> tuple[int, bytes]:
    req = urllib.request.Request(  # customer-built AWS host
        url, method="POST",
        data=urllib.parse.urlencode({"token": token, "client_id": client_id}).encode(),
        headers={**route_headers, "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _poll_endpoint(url: str, route_headers: dict, token: str, client_id: str) -> tuple[int, bytes]:
    """Poll a (refused) revoke until the hosted-UI hostname answers with the 401 a live
    endpoint gives. Transport errors (DNS not yet resolvable) and warm-up statuses retry."""
    deadline = time.monotonic() + ENDPOINT_READY_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            status, body = _post_revoke(url, route_headers, token, client_id)
            last = (status, body[:300])
            if status == 401:
                return status, body
        except (urllib.error.URLError, OSError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        time.sleep(2)
    raise AssertionError(
        f"hosted-UI revoke endpoint {url} never answered within {ENDPOINT_READY_TIMEOUT_S:.0f}s; last {last!r}"
    )


def _json(body: bytes) -> dict:
    try:
        return json.loads(body.decode() or "{}")
    except ValueError:
        return {}


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        out = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    keys = sorted((out or {}).get("AuthenticationResult", out or {}))
    raise AssertionError(f"call expected to fail SUCCEEDED (response keys {keys!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
