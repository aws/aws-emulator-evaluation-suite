"""add-custom-attributes-extends-schema."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "add-custom-attributes-extends-schema"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddCustomAttributes appends a new schema entry post pool-creation that becomes
    immediately settable/readable on users."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    schema_before = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"]["SchemaAttributes"]
    names_before = [a["Name"] for a in schema_before]
    assert "custom:loyalty_tier" not in names_before, names_before

    idp.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[
            {"Name": "loyalty_tier", "AttributeDataType": "String", "Mutable": True, "StringAttributeConstraints": {"MaxLength": "32"}}
        ],
    )

    schema_after = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"]["SchemaAttributes"]
    names_after = [a["Name"] for a in schema_after]
    assert "custom:loyalty_tier" in names_after, names_after

    username = ctx.unique_name("sim2real-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
            {"Name": "custom:loyalty_tier", "Value": "gold"},
        ],
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    attrs = {
        a["Name"]: a["Value"]
        for a in idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    }
    assert attrs.get("custom:loyalty_tier") == "gold", attrs

    idp.admin_update_user_attributes(
        UserPoolId=pool_id, Username=username, UserAttributes=[{"Name": "custom:loyalty_tier", "Value": "platinum"}]
    )
    attrs_after = {
        a["Name"]: a["Value"]
        for a in idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    }
    assert attrs_after.get("custom:loyalty_tier") == "platinum", attrs_after


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
