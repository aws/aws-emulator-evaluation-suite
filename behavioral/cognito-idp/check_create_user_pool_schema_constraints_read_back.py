"""create-user-pool-schema-constraints-read-back."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-user-pool-schema-constraints-read-back"
GROUP = "representation"
SERVICES = ["cognito-idp"]

_TENANT = {
    "AttributeDataType": "String",
    "DeveloperOnlyAttribute": False,
    "Mutable": True,
    "Name": "custom:tenant",
    "Required": False,
    "StringAttributeConstraints": {"MaxLength": "256", "MinLength": "1"},
}
_LEVEL = {
    "AttributeDataType": "Number",
    "DeveloperOnlyAttribute": False,
    "Mutable": False,
    "Name": "custom:level",
    "NumberAttributeConstraints": {"MaxValue": "100", "MinValue": "0"},
    "Required": False,
}
_EMAIL = {
    "AttributeDataType": "String",
    "DeveloperOnlyAttribute": False,
    "Mutable": True,
    "Name": "email",
    "Required": True,
    "StringAttributeConstraints": {"MaxLength": "2048", "MinLength": "0"},
}
_NICK = {
    "AttributeDataType": "String",
    "DeveloperOnlyAttribute": False,
    "Mutable": True,
    "Name": "custom:nick",
    "Required": False,
    "StringAttributeConstraints": {"MaxLength": "32"},
}
_SCORE = {
    "AttributeDataType": "Number",
    "DeveloperOnlyAttribute": False,
    "Mutable": True,
    "Name": "custom:score",
    "NumberAttributeConstraints": {},
    "Required": False,
}


def _schema(pool: dict) -> dict:
    """A user pool's SchemaAttributes list as a name -> entry dict."""
    return {a["Name"]: a for a in pool["SchemaAttributes"]}


def _custom_names(schema: dict) -> set:
    return {name for name in schema if name.startswith("custom:")}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserPool and DescribeUserPool return each Schema entry as sent, named custom:<name>,
    with its constraints as strings and the email default constraints; AddCustomAttributes entries
    read back the same way while the earlier entries stay unchanged.

    Reference: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SchemaAttributeType.html"""
    idp = ctx.client("cognito-idp")
    created = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-schema-"),
        Schema=[
            {"Name": "email", "AttributeDataType": "String", "Required": True, "Mutable": True},
            {
                "Name": "tenant",
                "AttributeDataType": "String",
                "DeveloperOnlyAttribute": False,
                "Mutable": True,
                "Required": False,
                "StringAttributeConstraints": {"MinLength": "1", "MaxLength": "256"},
            },
            {
                "Name": "level",
                "AttributeDataType": "Number",
                "DeveloperOnlyAttribute": False,
                "Mutable": False,
                "Required": False,
                "NumberAttributeConstraints": {"MinValue": "0", "MaxValue": "100"},
            },
        ],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]
    pool_id = created["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    on_create = _schema(created)
    assert on_create.get("custom:tenant") == _TENANT, (
        f"CreateUserPool must return custom:tenant as {_TENANT!r}, got {on_create.get('custom:tenant')!r}"
    )
    assert on_create.get("custom:level") == _LEVEL, (
        f"CreateUserPool must return custom:level as {_LEVEL!r}, got {on_create.get('custom:level')!r}"
    )
    assert on_create.get("email") == _EMAIL, (
        f"CreateUserPool must return email as {_EMAIL!r}, got {on_create.get('email')!r}"
    )

    described = _schema(idp.describe_user_pool(UserPoolId=pool_id)["UserPool"])
    assert described.get("custom:tenant") == _TENANT, (
        f"DescribeUserPool must return custom:tenant as {_TENANT!r}, got {described.get('custom:tenant')!r}"
    )
    assert described.get("custom:level") == _LEVEL, (
        f"DescribeUserPool must return custom:level as {_LEVEL!r}, got {described.get('custom:level')!r}"
    )
    assert described.get("email") == _EMAIL, (
        f"DescribeUserPool must return email as {_EMAIL!r}, got {described.get('email')!r}"
    )
    assert _custom_names(described) == {"custom:tenant", "custom:level"}, (
        f"the pool must hold exactly the two custom attributes it was created with, got "
        f"{sorted(_custom_names(described))}"
    )

    idp.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[
            {
                "Name": "nick",
                "AttributeDataType": "String",
                "Mutable": True,
                "StringAttributeConstraints": {"MaxLength": "32"},
            },
            {"Name": "score", "AttributeDataType": "Number", "Mutable": True},
        ],
    )
    after_add = _schema(idp.describe_user_pool(UserPoolId=pool_id)["UserPool"])
    assert after_add.get("custom:nick") == _NICK, (
        f"DescribeUserPool must return the added custom:nick as {_NICK!r}, got {after_add.get('custom:nick')!r}"
    )
    assert after_add.get("custom:score") == _SCORE, (
        f"DescribeUserPool must return the added custom:score as {_SCORE!r}, got {after_add.get('custom:score')!r}"
    )
    assert after_add.get("custom:tenant") == _TENANT, (
        f"AddCustomAttributes must leave custom:tenant as {_TENANT!r}, got {after_add.get('custom:tenant')!r}"
    )
    assert after_add.get("custom:level") == _LEVEL, (
        f"AddCustomAttributes must leave custom:level as {_LEVEL!r}, got {after_add.get('custom:level')!r}"
    )
    assert _custom_names(after_add) == {
        "custom:tenant",
        "custom:level",
        "custom:nick",
        "custom:score",
    }, (
        f"the pool must hold exactly four custom attributes after the add, got "
        f"{sorted(_custom_names(after_add))}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
