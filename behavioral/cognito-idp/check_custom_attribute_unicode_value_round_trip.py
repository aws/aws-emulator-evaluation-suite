"""custom-attribute-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-attribute-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["cognito-idp"]

_UNICODE_VALUE = "日本語-Ünïcödé-\u00df-\U0001f600-\u0391\u03b2\u03b3"  # CJK, latin-1 extended, emoji, Greek


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A multi-byte unicode custom attribute value written via AdminUpdateUserAttributes is
    returned byte-identical (no mangling/normalization/truncation) by AdminGetUser."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-attrpool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-attrpool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    idp.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[
            {
                "Name": "nick",
                "AttributeDataType": "String",
                "Mutable": True,
                "StringAttributeConstraints": {"MaxLength": "256"},
            }
        ],
    )

    username = ctx.unique_name("sim2real-attruser-")
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    idp.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "custom:nick", "Value": _UNICODE_VALUE}],
    )

    resp = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    attrs = {a["Name"]: a["Value"] for a in resp["UserAttributes"]}
    assert "custom:nick" in attrs, f"expected custom:nick in AdminGetUser attributes, got {sorted(attrs)}"
    assert attrs["custom:nick"] == _UNICODE_VALUE, (
        f"expected custom:nick == {_UNICODE_VALUE!r} byte-identical, got {attrs['custom:nick']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
