"""browser-origin-sign-up-response-carries-cors-headers."""
from __future__ import annotations

import json

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "browser-origin-sign-up-response-carries-cors-headers"
GROUP = "browser-cors"
SERVICES = ["cognito-idp"]

ORIGIN = "https://app.example.com"
EXPOSE = "x-amzn-RequestId,x-amzn-ErrorType,x-amzn-ErrorMessage,Date"


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


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An unsigned SignUp sent the way a browser sends it, with an Origin, is answered with
    Access-Control-Allow-Origin and the exposed headers, and creates the unconfirmed user it names.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-cors-"),
        UserPoolTags={"sim2real": GROUP},
    )["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool(UserPoolId=pool_id), "ResourceNotFoundException"))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-spa-"),
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-behav-cip-user-")
    email = f"{username}@example.com"
    url = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com")
    r = requests.post(
        url + "/",
        data=json.dumps({
            "ClientId": client_id,
            "Username": username,
            "Password": "Sim2Real!Passw0rd",
            "UserAttributes": [{"Name": "email", "Value": email}],
        }),
        headers={
            "Origin": ORIGIN,
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.SignUp",
        },
        timeout=30,
        verify=ctx.http_verify,
    )
    assert r.status_code == 200, f"unsigned SignUp answered {r.status_code}: {r.text[:300]!r}"
    assert r.headers.get("Access-Control-Allow-Origin") == "*", (
        f"Access-Control-Allow-Origin was {r.headers.get('Access-Control-Allow-Origin')!r}"
    )
    assert r.headers.get("Access-Control-Expose-Headers") == EXPOSE, (
        f"Access-Control-Expose-Headers was {r.headers.get('Access-Control-Expose-Headers')!r}"
    )
    assert r.headers.get("Content-Type") == "application/x-amz-json-1.1", (
        f"Content-Type was {r.headers.get('Content-Type')!r}"
    )
    body = r.json()
    assert sorted(body) == ["UserConfirmed", "UserSub"], f"SignUp body keys were {sorted(body)!r}"
    assert body["UserConfirmed"] is False, f"UserConfirmed was {body['UserConfirmed']!r}"

    # The browser call is a real sign-up: the signed admin read sees the same user and sub.
    user = c.admin_get_user(UserPoolId=pool_id, Username=username)
    attrs = {a["Name"]: a["Value"] for a in user["UserAttributes"]}
    assert user["UserStatus"] == "UNCONFIRMED", f"UserStatus was {user['UserStatus']!r}"
    assert attrs.get("sub") == body["UserSub"], (
        f"admin sub {attrs.get('sub')!r} differs from the UserSub SignUp returned"
    )
    assert attrs.get("email") == email, f"email was {attrs.get('email')!r}, expected {email!r}"
    assert attrs.get("email_verified") == "false", f"email_verified was {attrs.get('email_verified')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
