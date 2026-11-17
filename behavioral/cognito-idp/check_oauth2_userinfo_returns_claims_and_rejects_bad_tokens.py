"""oauth2-userinfo-returns-claims-and-rejects-bad-tokens."""
from __future__ import annotations

import http.cookiejar
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "oauth2-userinfo-returns-claims-and-rejects-bad-tokens"
GROUP = "hosted-oauth2"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
CALLBACK = "https://example.com/callback"
# A fresh prefix domain is ACTIVE in seconds but its hostname answers only after minutes, so the
# wait polls the login page within the 1800 s budget declared here.
ENDPOINT_READY_TIMEOUT_S = 1380.0


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """/oauth2/userInfo returns sub, email_verified, email and username matching AdminGetUser for an
    openid-scoped token; a malformed or non-openid token is 401 invalid_token and a missing header 400
    invalid_request, each with its exact body and a WWW-Authenticate naming the issuer."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-userinfo-pool-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool(UserPoolId=pool_id),
                             "ResourceNotFoundException"))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-userinfo-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        AllowedOAuthFlows=["code"], AllowedOAuthScopes=["openid", "email"],
        AllowedOAuthFlowsUserPoolClient=True, CallbackURLs=[CALLBACK],
        SupportedIdentityProviders=["COGNITO"],
    )["UserPoolClient"]["ClientId"]
    domain = ctx.unique_name("sim2real-behav-userinfo-")
    c.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id),
                             "ResourceNotFoundException", "InvalidParameterException"))
    base, route_headers = f"https://{domain}.auth.{ctx.region}.amazoncognito.com", {}
    realm = f"{c.meta.endpoint_url.rstrip('/')}/{pool_id}"

    username = ctx.unique_name("sim2real-behav-userinfo-user-")
    email = f"{username}@example.com"
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
                        UserAttributes=[{"Name": "email", "Value": email},
                                        {"Name": "email_verified", "Value": "true"}])
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD,
                              Permanent=True)
    attrs = {a["Name"]: a["Value"] for a in
             c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]}
    api_token = c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["AccessToken"]

    session = _Session(base, route_headers)
    login_query = urllib.parse.urlencode({"client_id": client_id, "response_type": "code",
                                          "scope": "openid email", "redirect_uri": CALLBACK})
    page = session.wait_ready("/login?" + login_query)

    refusals = [
        ("a malformed token", {"Authorization": "Bearer not-a-jwt"}, 401,
         {"error": "invalid_token", "error_description": "Access token format is not valid"},
         "INVALID_TOKEN"),
        ("an access token without the openid scope", {"Authorization": f"Bearer {api_token}"}, 401,
         {"error": "invalid_token",
          "error_description": "Access token does not contain the 'openid' scope"},
         "INVALID_TOKEN"),
        ("no Authorization header", {}, 400,
         {"error": "invalid_request",
          "error_description": "Authorization header required, but missing from request"},
         "INVALID_REQUEST"),
    ]
    for label, headers, want_status, want_body, want_error in refusals:
        status, got_headers, body = session.request("GET", "/oauth2/userInfo", headers=headers)
        assert (status, _json(body)) == (want_status, want_body), (
            f"userInfo with {label} returned HTTP {status!r} {body[:200]!r}"
        )
        challenge = got_headers.get("WWW-Authenticate")
        assert challenge == f"Bearer realm={realm}, error={want_error}", (
            f"userInfo with {label}: WWW-Authenticate was "
            f"{(challenge or '').replace(pool_id, '<pool>')!r}, expected realm <issuer>, "
            f"error={want_error}"
        )

    # Positive control: sign in through the hosted UI and exchange the code.
    csrf = re.search(r'name="_csrf" value="([^"]+)"', page)
    assert csrf, "the hosted-UI login page carried no _csrf form field"
    status, headers, body = session.request(
        "POST", "/login?" + login_query,
        data={"_csrf": csrf.group(1), "username": username, "password": PASSWORD,
              "signInSubmitButton": "Sign in"})
    location = headers.get("Location", "")
    code = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get("code")
    assert status == 302 and location.startswith(CALLBACK) and code, (
        f"hosted-UI sign-in returned HTTP {status!r} redirecting to {location.split('?')[0]!r}"
    )
    status, _, body = session.request(
        "POST", "/oauth2/token",
        data={"grant_type": "authorization_code", "client_id": client_id, "code": code[0],
              "redirect_uri": CALLBACK})
    tokens = _json(body)
    assert status == 200 and "access_token" in tokens, (
        f"code exchange returned HTTP {status!r} with members {sorted(tokens)!r}"
    )

    status, headers, body = session.request(
        "GET", "/oauth2/userInfo", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert status == 200, f"userInfo with an openid-scoped token returned HTTP {status!r} {body[:200]!r}"
    assert headers.get("Content-Type") == "application/json;charset=UTF-8", (
        f"userInfo Content-Type was {headers.get('Content-Type')!r}"
    )
    claims = _json(body)
    want = {"sub": attrs["sub"], "email_verified": "true", "email": email, "username": username}
    assert claims == want, (
        f"userInfo members were {sorted(claims)!r}; values equal to AdminGetUser's: "
        f"{ {k: claims.get(k) == v for k, v in want.items()}!r}"
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # the 302 to the callback is the answer
        return None


class _Session:
    """A cookie-keeping HTTP session against the hosted domain that does not follow redirects."""

    def __init__(self, base: str, route_headers: dict) -> None:
        self.base = base
        self.route_headers = route_headers
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), _NoRedirect)

    def request(self, method: str, path: str, *, headers: dict | None = None,
                data: dict | None = None) -> tuple[int, dict, bytes]:
        hdrs = {**self.route_headers, **(headers or {})}
        payload = None
        if data is not None:
            payload = urllib.parse.urlencode(data).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(self.base + path, data=payload, method=method, headers=hdrs)  # customer-built AWS host
        try:
            with self.opener.open(req, timeout=20) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def wait_ready(self, path: str) -> str:
        """Poll ``path`` until the hosted domain serves it 200; transport errors retry."""
        deadline = time.monotonic() + ENDPOINT_READY_TIMEOUT_S
        last = None
        while time.monotonic() < deadline:
            try:
                status, _, body = self.request("GET", path)
                last = status
                if status == 200:
                    return body.decode()
            except (urllib.error.URLError, OSError) as exc:
                last = f"{type(exc).__name__}: {exc}"
            time.sleep(2)
        raise AssertionError(
            f"the hosted-domain login page never answered within {ENDPOINT_READY_TIMEOUT_S:.0f}s; "
            f"last {last!r}"
        )


def _json(body: bytes) -> dict:
    try:
        return json.loads(body.decode() or "{}")
    except ValueError:
        return {"unparseable": body[:200].decode(errors="replace")}


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
