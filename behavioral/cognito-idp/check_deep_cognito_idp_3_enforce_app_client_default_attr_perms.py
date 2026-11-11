"""deep-cognito-idp-3-enforce-app-client-default-attr-perms."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-idp-3-enforce-app-client-default-attr-perms"
GROUP = "authorization"
SERVICES = ["cognito-idp"]


@tags(
    "axis:happy-path",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A client created without ReadAttributes or WriteAttributes describes with neither and reads
    and writes every attribute; narrowing them limits the same token at once (name withheld, a name
    write refused with NotAuthorizedException), and omitting both restores the default."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-dattr-"),
        Schema=[{"Name": "tier", "AttributeDataType": "String", "Mutable": True}],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-dattr-c-"),
        ExplicitAuthFlows=flows,
    )["UserPoolClient"]["ClientId"]

    desc = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert "ReadAttributes" not in desc and "WriteAttributes" not in desc, (
        f"a client created without attribute permissions must describe with neither key; got "
        f"ReadAttributes={desc.get('ReadAttributes')!r} WriteAttributes={desc.get('WriteAttributes')!r}"
    )

    username = ctx.unique_name("sim2real-behav-dattr-u-")
    password = _strong_password()
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=_strong_password(),
        UserAttributes=[
            {"Name": "email", "Value": "dattr@example.com"},
            {"Name": "name", "Value": "N0"},
            {"Name": "given_name", "Value": "G0"},
            {"Name": "custom:tier", "Value": "gold"},
        ],
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    token = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]

    admin_names = set(_admin_attrs(idp, pool_id, username))
    read_names = set(_user_attrs(idp, token))
    assert {"custom:tier", "email", "given_name", "name", "sub"} <= admin_names, (
        f"AdminGetUser should hold every attribute we set, got {sorted(admin_names)!r}"
    )
    assert read_names == admin_names, (
        f"default client GetUser must return exactly AdminGetUser's attribute set; "
        f"GetUser={sorted(read_names)!r} AdminGetUser={sorted(admin_names)!r}"
    )

    idp.update_user_attributes(
        AccessToken=token,
        UserAttributes=[{"Name": "name", "Value": "N1"}, {"Name": "custom:tier", "Value": "silver"}],
    )
    after_write = _admin_attrs(idp, pool_id, username)
    assert after_write.get("name") == "N1" and after_write.get("custom:tier") == "silver", (
        f"default client must be able to write standard and custom attributes; AdminGetUser shows "
        f"name={after_write.get('name')!r} custom:tier={after_write.get('custom:tier')!r}"
    )

    idp.update_user_pool_client(
        UserPoolId=pool_id, ClientId=client_id, ExplicitAuthFlows=flows,
        ReadAttributes=["email"], WriteAttributes=["given_name"],
    )
    narrowed = set(_user_attrs(idp, token))
    assert "name" not in narrowed and "custom:tier" not in narrowed and "email" in narrowed, (
        f"after narrowing to ReadAttributes=['email'] the SAME token must lose `name` and "
        f"`custom:tier` but keep `email`; GetUser returned {sorted(narrowed)!r}"
    )
    code, message = _error(lambda: idp.update_user_attributes(
        AccessToken=token, UserAttributes=[{"Name": "name", "Value": "N2"}],
    ))
    assert code == "NotAuthorizedException", (
        f"writing `name` after narrowing WriteAttributes returned {code!r}, expected NotAuthorizedException"
    )
    expected_message = "A client attempted to write unauthorized attribute"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert _admin_attrs(idp, pool_id, username).get("name") == "N1", (
        "refused `name` write must leave the value at 'N1'"
    )

    idp.update_user_pool_client(UserPoolId=pool_id, ClientId=client_id, ExplicitAuthFlows=flows)
    reset = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert "ReadAttributes" not in reset and "WriteAttributes" not in reset, (
        f"an update omitting both keys must restore the default (neither key); got "
        f"ReadAttributes={reset.get('ReadAttributes')!r} WriteAttributes={reset.get('WriteAttributes')!r}"
    )
    restored = set(_user_attrs(idp, token))
    assert restored == set(_admin_attrs(idp, pool_id, username)), (
        f"after reset GetUser must again return every attribute; got {sorted(restored)!r}"
    )


def _strong_password() -> str:
    return "Aa1!" + secrets.token_urlsafe(18)


def _admin_attrs(idp, pool_id: str, username: str) -> dict:
    items = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    return {a["Name"]: a["Value"] for a in items}


def _user_attrs(idp, token: str) -> dict:
    return {a["Name"]: a["Value"] for a in idp.get_user(AccessToken=token)["UserAttributes"]}


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
