"""browser-origin-unsigned-admin-create-user-rejected."""
from __future__ import annotations

import json

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "browser-origin-unsigned-admin-create-user-rejected"
GROUP = "browser-cors"
SERVICES = ["cognito-idp"]

ORIGIN = "https://app.example.com"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> dict:
    """The ClientError ``fn`` raises as {Code, Message}. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """From a browser origin, an unsigned AdminCreateUser is refused MissingAuthenticationToken with
    CORS headers so the page can read why, and creates no user; the signed call creates it.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-cors-"),
        UserPoolTags={"sim2real": GROUP},
    )["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool(UserPoolId=pool_id), "ResourceNotFoundException"))

    username = ctx.unique_name("sim2real-behav-cip-user-")
    url = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com")
    r = requests.post(
        url + "/",
        data=json.dumps({"UserPoolId": pool_id, "Username": username, "MessageAction": "SUPPRESS"}),
        headers={
            "Origin": ORIGIN,
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.AdminCreateUser",
        },
        timeout=30,
        verify=ctx.http_verify,
    )
    assert r.status_code == 400, f"unsigned AdminCreateUser answered {r.status_code}: {r.text[:300]!r}"
    assert r.headers.get("Access-Control-Allow-Origin") == "*", (
        f"Access-Control-Allow-Origin was {r.headers.get('Access-Control-Allow-Origin')!r}"
    )
    assert r.headers.get("x-amzn-ErrorType") == "MissingAuthenticationTokenException:", (
        f"x-amzn-ErrorType was {r.headers.get('x-amzn-ErrorType')!r}"
    )
    body = r.json()
    assert body == {
        "__type": "MissingAuthenticationTokenException",
        "message": "Missing Authentication Token",
    }, f"unsigned AdminCreateUser answered body {body!r}"

    # Effect absent: the refused request created nothing.
    err = _error(lambda: c.admin_get_user(UserPoolId=pool_id, Username=username))
    assert (err["Code"], err["Message"]) == ("UserNotFoundException", "User does not exist."), (
        f"AdminGetUser after the refused create answered {err!r}"
    )

    # Positive control: the identical request, signed, creates the user.
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    user = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert user["Username"] == username, f"signed create read back {user['Username']!r}"
    assert user["UserStatus"] == "FORCE_CHANGE_PASSWORD", f"UserStatus was {user['UserStatus']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
