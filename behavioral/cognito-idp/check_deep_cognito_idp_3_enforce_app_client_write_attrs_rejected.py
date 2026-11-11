"""deep-cognito-idp-3-enforce-app-client-write-attrs-rejected."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-idp-3-enforce-app-client-write-attrs-rejected"
GROUP = "authorization"
SERVICES = ["cognito-idp"]


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """With WriteAttributes=["given_name"], UpdateUserAttributes of name through the client is
    refused with NotAuthorizedException and the exact message and leaves name unchanged, while
    given_name is written and a twin client without permissions writes name."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-wattr-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
    restricted = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-wattr-r-"),
        ExplicitAuthFlows=flows,
        WriteAttributes=["given_name"],
    )["UserPoolClient"]["ClientId"]
    twin = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-wattr-d-"),
        ExplicitAuthFlows=flows,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-behav-wattr-u-")
    password = _strong_password()
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=_strong_password(),
        UserAttributes=[
            {"Name": "name", "Value": "Original Name"},
            {"Name": "given_name", "Value": "Original"},
        ],
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    r_token = _sign_in(idp, restricted, username, password)
    t_token = _sign_in(idp, twin, username, password)

    code, message = _error(lambda: idp.update_user_attributes(
        AccessToken=r_token, UserAttributes=[{"Name": "name", "Value": "Hijacked Name"}],
    ))
    assert code == "NotAuthorizedException", (
        f"writing `name` via a client whose WriteAttributes excludes it returned {code!r}, "
        f"expected NotAuthorizedException"
    )
    expected_message = "A client attempted to write unauthorized attribute"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    after_refusal = _admin_attrs(idp, pool_id, username)
    assert after_refusal.get("name") == "Original Name", (
        f"refused write must leave `name` intact, AdminGetUser shows {after_refusal.get('name')!r}"
    )

    idp.update_user_attributes(
        AccessToken=r_token, UserAttributes=[{"Name": "given_name", "Value": "Permitted"}],
    )
    after_permitted = _admin_attrs(idp, pool_id, username)
    assert after_permitted.get("given_name") == "Permitted", (
        f"restricted client may write `given_name` (in its WriteAttributes); AdminGetUser shows "
        f"{after_permitted.get('given_name')!r}"
    )
    assert after_permitted.get("name") == "Original Name", (
        f"`name` must still be the original after the permitted write, got {after_permitted.get('name')!r}"
    )

    idp.update_user_attributes(
        AccessToken=t_token, UserAttributes=[{"Name": "name", "Value": "Twin Changed Name"}],
    )
    after_twin = _admin_attrs(idp, pool_id, username)
    assert after_twin.get("name") == "Twin Changed Name", (
        f"twin client (default WriteAttributes) must be able to set `name`; AdminGetUser shows "
        f"{after_twin.get('name')!r}"
    )


def _strong_password() -> str:
    return "Aa1!" + secrets.token_urlsafe(18)


def _admin_attrs(idp, pool_id: str, username: str) -> dict:
    items = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    return {a["Name"]: a["Value"] for a in items}


def _sign_in(idp, client_id: str, username: str, password: str) -> str:
    resp = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in resp, f"expected tokens from USER_PASSWORD_AUTH, got {resp!r}"
    return resp["AuthenticationResult"]["AccessToken"]


class _UnexpectedSuccess(AssertionError):
    pass


def _error(fn) -> tuple[str, str]:
    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise _UnexpectedSuccess(f"call expected to be refused SUCCEEDED: {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
