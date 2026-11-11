"""user-password-sign-in-issues-tokens-that-resolve-the-user."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-password-sign-in-issues-tokens-that-resolve-the-user"
GROUP = "auth-state-machine"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _error(fn):
    """Return (Error.Code, HTTP status, Error.Message) of the ClientError fn raises; fail on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"), err.get(
            "Message"
        ) or ""
    raise AssertionError("the call succeeded; expected a refusal")


def _refusal(got, what):
    """(code, message) of an ``_error`` result, after grading its HTTP 4xx status."""
    code, status, message = got
    assert isinstance(status, int) and 400 <= status < 500, f"{what}: answered HTTP {status!r}, expected 4xx"
    return code, message


def _delete_pool_if_present(idp, pool_id):
    try:
        idp.delete_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _listed(idp, pool_id):
    token = None
    while True:
        page = idp.list_user_pools(MaxResults=60, **({"NextToken": token} if token else {}))
        if any(p["Id"] == pool_id for p in page.get("UserPools", [])):
            return True
        token = page.get("NextToken")
        if not token:
            return False


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """USER_PASSWORD_AUTH signs a confirmed user in unchallenged with Bearer ID/access/refresh
    tokens that GetUser and REFRESH_TOKEN_AUTH resolve to that user; after DeleteUserPool the
    pool is not found, unlisted, and refuses AdminCreateUser."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_if_present(idp, pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(FLOWS),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-cip-user-")
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    resp = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )
    assert "ChallengeName" not in resp, f"a confirmed user was challenged: {resp.get('ChallengeName')!r}"
    result = resp["AuthenticationResult"]
    for field in ("AccessToken", "IdToken"):
        token = result.get(field)
        assert isinstance(token, str) and token.count(".") == 2, f"{field} is missing or not a JWT"
    assert isinstance(result.get("RefreshToken"), str) and result["RefreshToken"], "RefreshToken is missing"
    assert result.get("TokenType") == "Bearer", f"TokenType {result.get('TokenType')!r}, expected Bearer"
    assert isinstance(result.get("ExpiresIn"), int) and result["ExpiresIn"] > 0, f"ExpiresIn {result.get('ExpiresIn')!r}"
    me = idp.get_user(AccessToken=result["AccessToken"])
    assert me["Username"] == username, f"GetUser resolved {me['Username']!r}, expected {username!r}"
    refreshed = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": result["RefreshToken"]},
    )["AuthenticationResult"]
    again = idp.get_user(AccessToken=refreshed["AccessToken"])
    assert again["Username"] == username, f"the refreshed access token resolved {again['Username']!r}"

    idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    idp.delete_user_pool(UserPoolId=pool_id)
    pool_gone = ("ResourceNotFoundException", f"User pool {pool_id} does not exist.")
    got = _refusal(_error(lambda: idp.describe_user_pool(UserPoolId=pool_id)), "DescribeUserPool after delete")
    assert got == pool_gone, f"DescribeUserPool after delete: expected {pool_gone}, got {got!r}"
    assert not _listed(idp, pool_id), "ListUserPools still lists the deleted pool"
    got = _refusal(
        _error(lambda: idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")),
        "AdminCreateUser in the deleted pool",
    )
    assert got == pool_gone, f"AdminCreateUser in the deleted pool: expected {pool_gone}, got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
