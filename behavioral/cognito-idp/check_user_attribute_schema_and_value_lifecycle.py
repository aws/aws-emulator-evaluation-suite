"""user-attribute-schema-and-value-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "user-attribute-schema-and-value-lifecycle"
GROUP = 'state-machine'
SERVICES = ['cognito-idp']

PASSWORD = "Str0ngPassw0rd!"
FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A custom attribute added by AddCustomAttributes, then set, updated and deleted per user
    (AdminUpdateUserAttributes, AdminDeleteUserAttributes, DeleteUserAttributes), is reflected
    consistently in AdminGetUser and GetUser."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), AutoVerifiedAttributes=["email"], UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    c.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[{"Name": "loyalty_id", "AttributeDataType": "String", "Mutable": True}],
    )

    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "custom:loyalty_id", "Value": "abc123"},
        ],
    )
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    desc = c.admin_get_user(UserPoolId=pool_id, Username=username)
    attrs = {a["Name"]: a["Value"] for a in desc["UserAttributes"]}
    assert attrs.get("custom:loyalty_id") == "abc123", attrs

    c.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "custom:loyalty_id", "Value": "xyz789"}],
    )
    desc2 = c.admin_get_user(UserPoolId=pool_id, Username=username)
    attrs2 = {a["Name"]: a["Value"] for a in desc2["UserAttributes"]}
    assert attrs2.get("custom:loyalty_id") == "xyz789", attrs2

    c.admin_delete_user_attributes(
        UserPoolId=pool_id, Username=username, UserAttributeNames=["custom:loyalty_id"]
    )
    desc3 = c.admin_get_user(UserPoolId=pool_id, Username=username)
    attrs3 = {a["Name"]: a["Value"] for a in desc3["UserAttributes"]}
    assert "custom:loyalty_id" not in attrs3, attrs3

    c.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "nickname", "Value": "temp-nick"}],
    )
    access_token = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["AccessToken"]
    got = c.get_user(AccessToken=access_token)
    attrs4 = {a["Name"]: a["Value"] for a in got["UserAttributes"]}
    assert attrs4.get("nickname") == "temp-nick", attrs4

    c.delete_user_attributes(AccessToken=access_token, UserAttributeNames=["nickname"])
    got2 = c.get_user(AccessToken=access_token)
    attrs5 = {a["Name"]: a["Value"] for a in got2["UserAttributes"]}
    assert "nickname" not in attrs5, attrs5


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
