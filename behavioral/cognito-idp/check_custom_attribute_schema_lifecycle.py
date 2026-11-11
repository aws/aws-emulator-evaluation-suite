"""custom-attribute-schema-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-attribute-schema-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_PASSWORD = "S1mParity!Behave2024"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddCustomAttributes extends the schema; Admin/self-service attribute delete clears the value."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    cognito.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[
            {"Name": "loyalty_tier", "AttributeDataType": "String", "Mutable": True},
            {"Name": "vip_note", "AttributeDataType": "String", "Mutable": True},
        ],
    )

    username = ctx.unique_name("sim2real-behav-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(
        lambda: _ignore_errors(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)

    # --- admin path: AdminUpdateUserAttributes -> AdminDeleteUserAttributes ---
    cognito.admin_update_user_attributes(
        UserPoolId=pool_id, Username=username, UserAttributes=[{"Name": "custom:loyalty_tier", "Value": "gold"}]
    )
    got = _attr_map(cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"])
    assert got.get("custom:loyalty_tier") == "gold", got

    cognito.admin_delete_user_attributes(
        UserPoolId=pool_id, Username=username, UserAttributeNames=["custom:loyalty_tier"]
    )
    got_after = _attr_map(cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"])
    assert "custom:loyalty_tier" not in got_after, got_after

    # --- self-service path: AdminUpdateUserAttributes (set) -> DeleteUserAttributes (clear) ---
    cognito.admin_update_user_attributes(
        UserPoolId=pool_id, Username=username, UserAttributes=[{"Name": "custom:vip_note", "Value": "priority"}]
    )
    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )["AuthenticationResult"]
    access_token = auth["AccessToken"]

    got_self = _attr_map(cognito.get_user(AccessToken=access_token)["UserAttributes"])
    assert got_self.get("custom:vip_note") == "priority", got_self

    cognito.delete_user_attributes(AccessToken=access_token, UserAttributeNames=["custom:vip_note"])
    got_self_after = _attr_map(cognito.get_user(AccessToken=access_token)["UserAttributes"])
    assert "custom:vip_note" not in got_self_after, got_self_after


def _attr_map(attrs) -> dict:
    return {a["Name"]: a["Value"] for a in attrs}


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
