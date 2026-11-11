"""email-username-sign-in-issues-tokens-with-the-client-validity-that-resolve-the-sub."""

from __future__ import annotations

import base64
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "email-username-sign-in-issues-tokens-with-the-client-validity-that-resolve-the-sub"
GROUP = "auth-state-machine"
SERVICES = ["cognito-idp"]

PASSWORD = "An0ther-Passw0rd#42"
FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
VALIDITY_MINUTES = 45


def _error(fn):
    """Return (Error.Code, HTTP status, Error.Message) of the ClientError fn raises; fail on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (
            err.get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            err.get("Message") or "",
        )
    raise AssertionError("the call succeeded; expected a refusal")


def _refusal(got, what):
    """(code, message) of an ``_error`` result, after grading its HTTP 4xx status."""
    code, status, message = got
    assert isinstance(status, int) and 400 <= status < 500, (
        f"{what}: answered HTTP {status!r}, expected 4xx"
    )
    return code, message


def _claims(token):
    """The JSON payload of a JWT."""
    parts = token.split(".")
    assert len(parts) == 3, "the token is not a three-part JWT"
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _delete_pool_if_present(idp, pool_id):
    try:
        idp.delete_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """In a pool whose username is the email, USER_PASSWORD_AUTH by email issues tokens that carry
    the client's 45-minute validity and name the user by its sub; GetUser and a refreshed access
    token resolve that sub, a wrong password is refused, and the deleted pool is not found."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-email-"),
        UsernameAttributes=["email"],
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_if_present(idp, pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(FLOWS),
        GenerateSecret=False,
        AccessTokenValidity=VALIDITY_MINUTES,
        IdTokenValidity=VALIDITY_MINUTES,
        TokenValidityUnits={"AccessToken": "minutes", "IdToken": "minutes"},
    )["UserPoolClient"]["ClientId"]
    email = f"jane.doe+{ctx.unique_name('')}@example.com"
    user = idp.admin_create_user(
        UserPoolId=pool_id,
        Username=email,
        MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "email", "Value": email},
            {"Name": "email_verified", "Value": "true"},
        ],
    )["User"]
    sub = {a["Name"]: a["Value"] for a in user["Attributes"]}["sub"]
    assert user["Username"] == sub, (
        "with an email username the user's Username must be its sub, not the email"
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=email, Password=PASSWORD, Permanent=True
    )

    resp = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": email, "PASSWORD": PASSWORD},
    )
    assert "ChallengeName" not in resp, (
        f"a confirmed user was challenged: {resp.get('ChallengeName')!r}"
    )
    result = resp["AuthenticationResult"]
    seconds = VALIDITY_MINUTES * 60
    assert (result.get("TokenType"), result.get("ExpiresIn")) == ("Bearer", seconds), (
        f"(TokenType, ExpiresIn) {(result.get('TokenType'), result.get('ExpiresIn'))!r}, expected ('Bearer', {seconds})"
    )
    assert isinstance(result.get("RefreshToken"), str) and result["RefreshToken"], (
        "RefreshToken is missing"
    )
    id_claims = _claims(result["IdToken"])
    got = {k: id_claims.get(k) for k in ("token_use", "aud", "sub", "cognito:username", "email")}
    want = {
        "token_use": "id",
        "aud": client_id,
        "sub": sub,
        "cognito:username": sub,
        "email": email,
    }
    assert got == want, f"IdToken claims {got!r}, expected {want!r}"
    assert id_claims["exp"] - id_claims["iat"] == seconds, (
        f"IdToken lifetime {id_claims['exp'] - id_claims['iat']}s, expected {seconds}s"
    )
    access = _claims(result["AccessToken"])
    got = {k: access.get(k) for k in ("token_use", "client_id", "sub", "username")}
    want = {"token_use": "access", "client_id": client_id, "sub": sub, "username": sub}
    assert got == want, f"AccessToken claims {got!r}, expected {want!r}"
    assert access["exp"] - access["iat"] == seconds, (
        f"AccessToken lifetime {access['exp'] - access['iat']}s, expected {seconds}s"
    )

    me = idp.get_user(AccessToken=result["AccessToken"])
    attrs = {a["Name"]: a["Value"] for a in me["UserAttributes"]}
    assert (me["Username"], attrs.get("email"), attrs.get("sub")) == (sub, email, sub), (
        f"GetUser resolved Username/email/sub {(me['Username'], attrs.get('email'), attrs.get('sub'))!r}"
    )
    refreshed = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": result["RefreshToken"]},
    )["AuthenticationResult"]
    assert refreshed.get("ExpiresIn") == seconds, (
        f"refreshed ExpiresIn {refreshed.get('ExpiresIn')!r}, expected {seconds}"
    )
    assert "RefreshToken" not in refreshed, (
        "REFRESH_TOKEN_AUTH returned a new RefreshToken without rotation enabled"
    )
    assert idp.get_user(AccessToken=refreshed["AccessToken"])["Username"] == sub, (
        "the refreshed token resolves another user"
    )

    got = _refusal(
        _error(
            lambda: idp.initiate_auth(
                ClientId=client_id,
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={"USERNAME": email, "PASSWORD": PASSWORD + "x"},
            )
        ),
        "USER_PASSWORD_AUTH with a wrong password",
    )
    assert got == ("NotAuthorizedException", "Incorrect username or password."), (
        f"USER_PASSWORD_AUTH with a wrong password: got {got!r}"
    )

    idp.admin_delete_user(UserPoolId=pool_id, Username=email)
    idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    idp.delete_user_pool(UserPoolId=pool_id)
    pool_gone = ("ResourceNotFoundException", f"User pool {pool_id} does not exist.")
    got = _refusal(
        _error(lambda: idp.describe_user_pool(UserPoolId=pool_id)), "DescribeUserPool after delete"
    )
    assert got == pool_gone, f"DescribeUserPool after delete: expected {pool_gone}, got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
