"""immutable-custom-attribute-update-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "immutable-custom-attribute-update-rejected"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminUpdateUserAttributes on a Mutable=False custom attribute fails with InvalidParameterException
    and its exact message and leaves the original value, while a mutable attribute on the same user
    updates."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    idp.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[
            {"Name": "sim2realfixed", "AttributeDataType": "String", "Mutable": False},
            {"Name": "sim2realflex", "AttributeDataType": "String", "Mutable": True},
        ],
    )
    fixed_attr = "custom:sim2realfixed"
    flex_attr = "custom:sim2realflex"

    username = ctx.unique_name("sim2real-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": fixed_attr, "Value": "original"}, {"Name": flex_attr, "Value": "original"}],
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    # Negative: the immutable attribute rejects a later update.
    code, code_message = _error(
        lambda: idp.admin_update_user_attributes(
            UserPoolId=pool_id, Username=username, UserAttributes=[{"Name": fixed_attr, "Value": "changed"}]
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    code_expected = f"user.{fixed_attr}: Attribute cannot be updated.\n"
    assert code_message == code_expected, (
        f"expected message {code_expected!r}, got {code_message!r}"
    )

    attrs_after = {
        a["Name"]: a["Value"] for a in idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    }
    assert attrs_after[fixed_attr] == "original", (
        f"immutable attribute value changed despite the rejected update: {attrs_after[fixed_attr]!r}"
    )

    # Positive control: the mutable sibling attribute on the same user updates fine.
    idp.admin_update_user_attributes(
        UserPoolId=pool_id, Username=username, UserAttributes=[{"Name": flex_attr, "Value": "changed"}]
    )
    attrs_final = {
        a["Name"]: a["Value"] for a in idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    }
    assert attrs_final[flex_attr] == "changed", f"mutable attribute failed to update: {attrs_final[flex_attr]!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
