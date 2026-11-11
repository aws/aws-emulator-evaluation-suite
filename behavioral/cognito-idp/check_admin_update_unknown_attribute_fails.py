"""admin-update-unknown-attribute-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-update-unknown-attribute-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminUpdateUserAttributes with an attribute absent from the schema is refused with
    InvalidParameterException and the exact message and stores nothing, while an in-schema write
    succeeds; after AddCustomAttributes the same write is stored."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))

    # positive control: an in-schema attribute update succeeds and is visible on an
    # independent read, so the pool/user wiring is proven healthy before we assert a rejection.
    c.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "nickname", "Value": "sim2real-control-nick"}],
    )
    control_attrs = {
        a["Name"]: a["Value"]
        for a in c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    }
    assert control_attrs.get("nickname") == "sim2real-control-nick", (
        f"expected the in-schema control update to persist, got {control_attrs.get('nickname')}"
    )

    try:
        c.admin_update_user_attributes(
            UserPoolId=pool_id,
            Username=username,
            UserAttributes=[{"Name": "custom:not_in_schema", "Value": "x"}],
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code, msg = err.get("Code"), err.get("Message")
    else:
        raise AssertionError("expected an off-schema attribute write to be rejected, but it succeeded")
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for an off-schema attribute, got {code}"
    )
    assert msg == "user.custom:not_in_schema: Attribute does not exist in the schema.\n", f"expected the exact {code} message, got {msg!r}"

    # effect-absent: an independent read proves the rejected write never landed.
    rejected_attrs = {
        a["Name"]: a["Value"]
        for a in c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    }
    assert "custom:not_in_schema" not in rejected_attrs, (
        f"off-schema attribute must not appear after a rejected write, got {rejected_attrs}"
    )

    # restore: the schema is append-only, so defining the attribute is how this negative
    # becomes valid. The identical call must now succeed, proving the schema was the boundary.
    c.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[
            {"Name": "not_in_schema", "AttributeDataType": "String", "Mutable": True, "StringAttributeConstraints": {"MaxLength": "32"}}
        ],
    )
    c.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "custom:not_in_schema", "Value": "x"}],
    )
    restored_attrs = {
        a["Name"]: a["Value"]
        for a in c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    }
    assert restored_attrs.get("custom:not_in_schema") == "x", (
        f"expected the identical write to succeed once the attribute is in schema, got {restored_attrs.get('custom:not_in_schema')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
