"""empty-vs-absent-custom-attribute-distinction."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "empty-vs-absent-custom-attribute-distinction"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A custom attribute created with an empty string is absent from AdminGetUser, exactly like one
    never supplied, while the same attribute created with a value reads back that value."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-emptyattrpool-"),
        Schema=[{"Name": "note", "AttributeDataType": "String", "Mutable": True, "Required": False}],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-emptyattrpool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    user_with_empty = ctx.unique_name("sim2real-user-empty-")
    user_without = ctx.unique_name("sim2real-user-absent-")
    user_with_value = ctx.unique_name("sim2real-user-value-")

    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=user_with_empty,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "custom:note", "Value": ""}],
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=user_with_empty))

    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=user_without,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=user_without))

    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=user_with_value,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "custom:note", "Value": "hello"}],
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=user_with_value))

    attrs_with_empty = {
        a["Name"]: a.get("Value")
        for a in cognito.admin_get_user(UserPoolId=pool_id, Username=user_with_empty)["UserAttributes"]
    }
    attrs_without = {
        a["Name"]: a.get("Value")
        for a in cognito.admin_get_user(UserPoolId=pool_id, Username=user_without)["UserAttributes"]
    }
    attrs_with_value = {
        a["Name"]: a.get("Value")
        for a in cognito.admin_get_user(UserPoolId=pool_id, Username=user_with_value)["UserAttributes"]
    }

    assert "custom:note" not in attrs_with_empty, (
        "an explicit empty-string custom attribute was preserved as a present, empty-valued "
        "attribute by AdminGetUser; real Cognito normalizes it away entirely"
    )
    assert "custom:note" not in attrs_without, "an attribute never supplied at creation appeared anyway"
    assert attrs_with_empty.get("custom:note") == attrs_without.get("custom:note"), (
        "an explicit empty-string custom attribute is NOT represented identically to an omitted "
        "one, even though real Cognito normalizes both to 'absent'"
    )
    assert attrs_with_value.get("custom:note") == "hello", (
        "a genuinely non-empty custom attribute value was not preserved by AdminGetUser "
        "(the write path for this attribute is broken, not just empty-string normalization)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
