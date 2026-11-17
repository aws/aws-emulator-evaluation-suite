"""cors-unsigned-initiate-auth-and-global-sign-out-carry-allow-origin."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cors-unsigned-initiate-auth-and-global-sign-out-carry-allow-origin"
GROUP = "cors"
SERVICES = ["cognito-idp"]

_ORIGIN = "https://app.example.com"
_PASSWORD = "Sup3r-Secret-Passw0rd!"
_WRONG_PASSWORD = "Wr0ng-Secret-Passw0rd!"

_EXPOSE_HEADERS = "x-amzn-RequestId,x-amzn-ErrorType,x-amzn-ErrorMessage,Date"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CORS preflight to the Cognito IdP endpoint, and an unsigned InitiateAuth and
    GlobalSignOut sent with an Origin, each answer the endpoint's Access-Control-* headers;
    an unsigned InitiateAuth refused for a wrong password carries them too."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cors-pool-"),
        Policies={"PasswordPolicy": {"MinimumLength": 8, "RequireUppercase": False,
                                     "RequireLowercase": False, "RequireNumbers": False,
                                     "RequireSymbols": False}},
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool(UserPoolId=pool_id),
                             "ResourceNotFoundException"))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cors-client-"),
        GenerateSecret=False, ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"],
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-cors-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
                        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"},
                                        {"Name": "email_verified", "Value": "true"}])
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD,
                              Permanent=True)

    url = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com/")

    status, headers, body = _http(
        ctx, "OPTIONS", url,
        {"Origin": _ORIGIN, "Access-Control-Request-Method": "POST",
         "Access-Control-Request-Headers": "content-type,x-amz-target"},
    )
    assert status == 200, f"the preflight answered {status}, not 200: {body[:300]!r}"
    want_preflight = {
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "content-type,x-amz-target",
        "access-control-allow-methods": "POST",
        "access-control-expose-headers": _EXPOSE_HEADERS,
        "access-control-max-age": "172800",
    }
    got_preflight = {k: headers[k] for k in want_preflight if k in headers}
    assert got_preflight == want_preflight, (
        f"the preflight's CORS headers are {got_preflight!r}, expected {want_preflight!r}"
    )

    status, headers, body = _call(ctx, url, "InitiateAuth", {
        "ClientId": client_id, "AuthFlow": "USER_PASSWORD_AUTH",
        "AuthParameters": {"USERNAME": username, "PASSWORD": _PASSWORD},
    })
    assert status == 200, f"the unsigned InitiateAuth answered {status}, not 200: {body[:300]!r}"
    auth = json.loads(body)["AuthenticationResult"]
    assert auth["TokenType"] == "Bearer", f"TokenType was {auth['TokenType']!r}, expected 'Bearer'"
    access_token = auth["AccessToken"]
    assert access_token.count(".") == 2, (
        f"AccessToken {access_token!r} is not a 3-segment JWT"
    )
    _assert_simple_cors(headers, "the unsigned InitiateAuth")

    status, headers, body = _call(ctx, url, "GlobalSignOut", {"AccessToken": access_token})
    assert status == 200, f"the unsigned GlobalSignOut answered {status}, not 200: {body[:300]!r}"
    _assert_simple_cors(headers, "the unsigned GlobalSignOut")

    # Prove the sign-out's effect with a read: the revoked access token is refused.
    code, message = _error(lambda: c.get_user(AccessToken=access_token))
    assert (code, message) == ("NotAuthorizedException", "Access Token has been revoked"), (
        f"GetUser with the signed-out token gave {code}: {message!r}"
    )

    status, headers, body = _call(ctx, url, "InitiateAuth", {
        "ClientId": client_id, "AuthFlow": "USER_PASSWORD_AUTH",
        "AuthParameters": {"USERNAME": username, "PASSWORD": _WRONG_PASSWORD},
    })
    assert status == 400, f"the wrong-password InitiateAuth answered {status}, not 400: {body[:300]!r}"
    err = json.loads(body)
    assert (err.get("__type"), err.get("message")) == (
        "NotAuthorizedException", "Incorrect username or password."
    ), f"the wrong-password InitiateAuth gave {err!r}"
    _assert_simple_cors(headers, "the wrong-password InitiateAuth")


def _assert_simple_cors(headers: dict, label: str) -> None:
    """``headers`` carries the endpoint's Access-Control-Allow-Origin and -Expose-Headers."""
    got = {k: headers[k] for k in ("access-control-allow-origin", "access-control-expose-headers")
           if k in headers}
    want = {"access-control-allow-origin": "*", "access-control-expose-headers": _EXPOSE_HEADERS}
    assert got == want, f"{label}'s CORS headers are {got!r}, expected {want!r}"


def _call(ctx, url: str, target: str, body: dict) -> tuple[int, dict, bytes]:
    """An unsigned POST naming ``target`` on ``AWSCognitoIdentityProviderService``, with Origin."""
    return _http(ctx, "POST", url, {
        "Origin": _ORIGIN, "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": f"AWSCognitoIdentityProviderService.{target}",
    }, json.dumps(body).encode())


def _ssl_context(verify):
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http(ctx, method: str, url: str, headers: dict, data: bytes | None = None):
    """(status, lower-cased headers, body) of a raw request; an HTTP error status is returned."""
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=30, context=_ssl_context(ctx.http_verify)) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
