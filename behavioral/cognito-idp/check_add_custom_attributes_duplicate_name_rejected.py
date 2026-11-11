"""add-custom-attributes-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "add-custom-attributes-duplicate-name-rejected"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddCustomAttributes refuses to redefine a custom attribute name that already
    exists in the pool's schema (the schema is append-only, never mutable in place)."""
    idp = ctx.client("cognito-idp")
    # NOTE: "username" is not one of the standard attributes that may carry
    # Required=True (AWS rejects CreateUserPool with InvalidParameterException
    # "Required custom attributes are not supported currently" in that case,
    # since the username attribute is always implicitly present). Only declare
    # the custom "tier" attribute here.
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        Schema=[
            {"Name": "tier", "AttributeDataType": "String", "Mutable": True},
        ],
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    schema = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"]["SchemaAttributes"]
    assert any(a["Name"] == "custom:tier" for a in schema), (
        f"expected custom:tier in the pool schema right after CreateUserPool, got {sorted(a['Name'] for a in schema)}"
    )

    # Positive control: AddCustomAttributes must generally work on this pool, so the
    # coming rejection can be attributed to the duplicate name and not to a target
    # that refuses every AddCustomAttributes call regardless of input.
    idp.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[{"Name": "region", "AttributeDataType": "String", "Mutable": True}],
    )
    schema_with_control = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"]["SchemaAttributes"]
    assert any(a["Name"] == "custom:region" for a in schema_with_control), (
        f"positive control failed: AddCustomAttributes(region) should have appended custom:region, "
        f"got {sorted(a['Name'] for a in schema_with_control)}"
    )

    code, message = _error(
        lambda: idp.add_custom_attributes(
            UserPoolId=pool_id,
            CustomAttributes=[{"Name": "tier", "AttributeDataType": "String", "Mutable": True}],
        )
    )
    assert (code, message) == ("InvalidParameterException", "Entity Type: USER, Message: AttributeName: tier, DataType: STRING, Error: Attribute name is not unique"), f"expected InvalidParameterException, got {(code, message)!r}"

    schema_after = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"]["SchemaAttributes"]
    assert sum(1 for a in schema_after if a["Name"] == "custom:tier") == 1, (
        f"the rejected redefinition must not duplicate custom:tier in the schema, got "
        f"{[a['Name'] for a in schema_after if a['Name'] == 'custom:tier']}"
    )
    assert sum(1 for a in schema_after if a["Name"] == "custom:region") == 1, (
        f"the rejected call on 'tier' must not disturb the earlier custom:region addition, got "
        f"{[a['Name'] for a in schema_after if a['Name'] == 'custom:region']}"
    )


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds raises: a target that
    accepts what AWS refuses must fail loudly, never as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
