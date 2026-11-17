"""browser-origin-sign-up-missing-required-attribute-rejected."""
from __future__ import annotations

import json

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "browser-origin-sign-up-missing-required-attribute-rejected"
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


def _error(fn) -> dict:
    """The ClientError ``fn`` raises as {Code, Message}. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _browser_sign_up(ctx, client_id: str, username: str, attributes: list):
    url = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com")
    return requests.post(
        url + "/",
        data=json.dumps({
            "ClientId": client_id,
            "Username": username,
            "Password": "Sim2Real!Passw0rd",
            "UserAttributes": attributes,
        }),
        headers={
            "Origin": ORIGIN,
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.SignUp",
        },
        timeout=30,
        verify=ctx.http_verify,
    )


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A browser SignUp missing a schema-required attribute is refused with a body and error-type
    header a browser may read (CORS headers on the 400), creates no user, and succeeds once supplied.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-cors-"),
        Schema=[{"Name": "name", "AttributeDataType": "String", "Required": True, "Mutable": True}],
        UserPoolTags={"sim2real": GROUP},
    )["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool(UserPoolId=pool_id), "ResourceNotFoundException"))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-spa-"),
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-behav-cip-user-")
    r = _browser_sign_up(ctx, client_id, username, [])
    assert r.status_code == 400, f"SignUp without name answered {r.status_code}: {r.text[:300]!r}"
    assert r.headers.get("Access-Control-Allow-Origin") == "*", (
        f"Access-Control-Allow-Origin on the 400 was {r.headers.get('Access-Control-Allow-Origin')!r}"
    )
    assert r.headers.get("Access-Control-Expose-Headers") == EXPOSE, (
        f"Access-Control-Expose-Headers on the 400 was {r.headers.get('Access-Control-Expose-Headers')!r}"
    )
    assert r.headers.get("x-amzn-ErrorType") == "InvalidParameterException:", (
        f"x-amzn-ErrorType was {r.headers.get('x-amzn-ErrorType')!r}"
    )
    body = r.json()
    assert body == {
        "__type": "InvalidParameterException",
        "message": "Attributes did not conform to the schema: name.formatted: "
                   "The attribute name.formatted is required",
    }, f"SignUp without name answered body {body!r}"

    # Effect absent: no user exists under the refused username.
    err = _error(lambda: c.admin_get_user(UserPoolId=pool_id, Username=username))
    assert (err["Code"], err["Message"]) == ("UserNotFoundException", "User does not exist."), (
        f"AdminGetUser after the refused SignUp answered {err!r}"
    )

    # Positive control: the same browser request with the required attribute creates the user.
    ok = _browser_sign_up(ctx, client_id, username, [{"Name": "name", "Value": "Jane Doe"}])
    assert ok.status_code == 200, f"SignUp with name answered {ok.status_code}: {ok.text[:300]!r}"
    assert ok.headers.get("Access-Control-Allow-Origin") == "*", (
        f"Access-Control-Allow-Origin on the 200 was {ok.headers.get('Access-Control-Allow-Origin')!r}"
    )
    attrs = {a["Name"]: a["Value"] for a in c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]}
    assert attrs.get("name") == "Jane Doe", f"name after the accepted SignUp was {attrs.get('name')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
