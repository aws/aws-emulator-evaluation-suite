"""custom-attribute-schema-is-append-only."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "custom-attribute-schema-is-append-only"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']


def _error(fn) -> tuple[str, str]:
    """Run fn and return the AWS error code and message it raised. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _attrs(user: dict) -> dict:
    """AdminGetUser's UserAttributes list as a name -> value dict."""
    return {a["Name"]: a["Value"] for a in user.get("UserAttributes", [])}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A pool's custom-attribute schema is append-only: an existing custom attribute cannot be
    redefined, deleting a user's value does not free the slot, and String/Number constraints reject
    out-of-bound values while a new attribute name still appends.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html"""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    c.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[
            {
                "Name": "tenant",
                "AttributeDataType": "String",
                "Mutable": True,
                "StringAttributeConstraints": {"MinLength": "1", "MaxLength": "8"},
            },
            {
                "Name": "level",
                "AttributeDataType": "Number",
                "Mutable": True,
                "NumberAttributeConstraints": {"MinValue": "1", "MaxValue": "10"},
            },
        ],
    )

    schema = {
        a["Name"]: a
        for a in c.describe_user_pool(UserPoolId=pool_id)["UserPool"]["SchemaAttributes"]
    }
    assert "custom:tenant" in schema, (
        f"AddCustomAttributes must expose the attribute as 'custom:tenant' in the pool schema, "
        f"got {sorted(schema)}"
    )
    assert schema["custom:tenant"]["AttributeDataType"] == "String", (
        f"custom:tenant must be a String attribute, got "
        f"{schema['custom:tenant']['AttributeDataType']}"
    )
    assert schema["custom:level"]["AttributeDataType"] == "Number", (
        f"custom:level must be a Number attribute, got "
        f"{schema['custom:level']['AttributeDataType']}"
    )
    assert schema["custom:level"].get("NumberAttributeConstraints", {}).get("MaxValue") == "10", (
        f"the pool schema must round-trip NumberAttributeConstraints.MaxValue='10', got "
        f"{schema['custom:level'].get('NumberAttributeConstraints')}"
    )

    username = ctx.unique_name("sim2real-behav-cipuser")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "custom:tenant", "Value": "acme"},
            {"Name": "custom:level", "Value": "7"},
        ],
    )
    stored = _attrs(c.admin_get_user(UserPoolId=pool_id, Username=username))
    assert stored.get("custom:tenant") == "acme", (
        f"expected custom:tenant='acme', got {stored.get('custom:tenant')}"
    )
    assert stored.get("custom:level") == "7", (
        f"expected custom:level='7', got {stored.get('custom:level')}"
    )

    # --- declared constraints are enforced, and a rejected write leaves the value intact ---
    over_range, over_range_message = _error(
        lambda: c.admin_update_user_attributes(
            UserPoolId=pool_id,
            Username=username,
            UserAttributes=[{"Name": "custom:level", "Value": "99"}],
        )
    )
    assert over_range == "InvalidParameterException", (
        f"custom:level='99' violates NumberAttributeConstraints 1..10 and must fail with "
        f"InvalidParameterException, got {over_range}"
    )
    expected_over_range = "user.custom:level: Number must be less than 10\n"
    assert over_range_message == expected_over_range, (
        f"expected message {expected_over_range!r}, got {over_range_message!r}"
    )
    too_long, too_long_message = _error(
        lambda: c.admin_update_user_attributes(
            UserPoolId=pool_id,
            Username=username,
            UserAttributes=[{"Name": "custom:tenant", "Value": "waytoolongvalue"}],
        )
    )
    assert too_long == "InvalidParameterException", (
        f"a 15-character custom:tenant violates StringAttributeConstraints MaxLength=8 and "
        f"must fail with InvalidParameterException, got {too_long}"
    )
    expected_too_long = "user.custom:tenant: String must be no longer than 8 characters\n"
    assert too_long_message == expected_too_long, (
        f"expected message {expected_too_long!r}, got {too_long_message!r}"
    )
    after_rejects = _attrs(c.admin_get_user(UserPoolId=pool_id, Username=username))
    assert after_rejects.get("custom:level") == "7", (
        f"the rejected out-of-range write must leave custom:level at '7', got "
        f"{after_rejects.get('custom:level')}"
    )
    assert after_rejects.get("custom:tenant") == "acme", (
        f"the rejected over-length write must leave custom:tenant at 'acme', got "
        f"{after_rejects.get('custom:tenant')}"
    )

    # --- the schema entry cannot be redefined ---
    redefine, redefine_message = _error(
        lambda: c.add_custom_attributes(
            UserPoolId=pool_id,
            CustomAttributes=[
                {
                    "Name": "tenant",
                    "AttributeDataType": "String",
                    "Mutable": True,
                    "StringAttributeConstraints": {"MinLength": "1", "MaxLength": "256"},
                }
            ],
        )
    )
    assert redefine == "InvalidParameterException", (
        f"re-adding an existing custom attribute must fail with InvalidParameterException, got "
        f"{redefine}"
    )
    expected_redefine = "Entity Type: USER, Message: AttributeName: tenant, DataType: STRING, Error: Attribute name is not unique"
    assert redefine_message == expected_redefine, (
        f"expected message {expected_redefine!r}, got {redefine_message!r}"
    )
    unchanged = {
        a["Name"]: a
        for a in c.describe_user_pool(UserPoolId=pool_id)["UserPool"]["SchemaAttributes"]
    }["custom:tenant"]
    assert unchanged.get("StringAttributeConstraints", {}).get("MaxLength") == "8", (
        f"the refused redefinition must not have widened MaxLength; got "
        f"{unchanged.get('StringAttributeConstraints')}"
    )

    # --- deleting the user's VALUE does not free the schema slot ---
    c.admin_delete_user_attributes(
        UserPoolId=pool_id, Username=username, UserAttributeNames=["custom:tenant"]
    )
    after_delete = _attrs(c.admin_get_user(UserPoolId=pool_id, Username=username))
    assert "custom:tenant" not in after_delete, (
        f"AdminDeleteUserAttributes must remove the user's custom:tenant value, still present "
        f"as {after_delete.get('custom:tenant')!r}"
    )
    schema_after_delete = {
        a["Name"]
        for a in c.describe_user_pool(UserPoolId=pool_id)["UserPool"]["SchemaAttributes"]
    }
    assert "custom:tenant" in schema_after_delete, (
        "custom attributes can never be deleted from a pool schema — custom:tenant "
        f"disappeared from the schema after its value was removed: {sorted(schema_after_delete)}"
    )
    still_taken, still_taken_message = _error(
        lambda: c.add_custom_attributes(
            UserPoolId=pool_id,
            CustomAttributes=[{"Name": "tenant", "AttributeDataType": "String"}],
        )
    )
    assert still_taken == "InvalidParameterException", (
        f"the custom:tenant schema slot must stay taken after the value was deleted; expected "
        f"InvalidParameterException, got {still_taken}"
    )
    expected_still_taken = "Entity Type: USER, Message: AttributeName: tenant, DataType: STRING, Error: Attribute name is not unique"
    assert still_taken_message == expected_still_taken, (
        f"expected message {expected_still_taken!r}, got {still_taken_message!r}"
    )

    # --- control: a genuinely new attribute name still appends fine ---
    c.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[
            {
                "Name": "region_code",
                "AttributeDataType": "String",
                "Mutable": True,
                "StringAttributeConstraints": {"MinLength": "1", "MaxLength": "16"},
            }
        ],
    )
    final_schema = {
        a["Name"]
        for a in c.describe_user_pool(UserPoolId=pool_id)["UserPool"]["SchemaAttributes"]
    }
    assert {"custom:tenant", "custom:level", "custom:region_code"} <= final_schema, (
        f"the pool schema must retain every added custom attribute, got {sorted(final_schema)}"
    )
    c.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "custom:region_code", "Value": "usw2"}],
    )
    final_attrs = _attrs(c.admin_get_user(UserPoolId=pool_id, Username=username))
    assert final_attrs.get("custom:region_code") == "usw2", (
        f"expected custom:region_code='usw2', got {final_attrs.get('custom:region_code')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
