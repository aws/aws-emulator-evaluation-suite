"""custom-attribute-usable-after-add."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-attribute-usable-after-add"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A custom attribute added via AddCustomAttributes can immediately be set through
    AdminUpdateUserAttributes and is returned by AdminGetUser."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-customattr-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-customattr"},
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool(idp, pool_id))

    idp.add_custom_attributes(
        UserPoolId=pool_id,
        CustomAttributes=[
            {
                "Name": "loyalty_tier",
                "AttributeDataType": "String",
                "Mutable": True,
                "StringAttributeConstraints": {"MinLength": "0", "MaxLength": "64"},
            }
        ],
    )

    username = ctx.unique_name("sim2real-customattr-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
    )

    before = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    before_names = {a["Name"] for a in before}
    assert "custom:loyalty_tier" not in before_names, before_names

    idp.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "custom:loyalty_tier", "Value": "gold"}],
    )

    after = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    values = {a["Name"]: a["Value"] for a in after}
    assert values.get("custom:loyalty_tier") == "gold", values

    idp.delete_user_pool(UserPoolId=pool_id)
    try:
        idp.describe_user_pool(UserPoolId=pool_id)
    except idp.exceptions.ResourceNotFoundException as exc:
        message = exc.response["Error"].get("Message")
        assert message == f"User pool {pool_id} does not exist.", message
    else:
        raise AssertionError(f"user pool {pool_id} still describable after DeleteUserPool")


def _delete_pool(idp, pool_id):
    """Delete the pool unless the check already deleted it."""
    try:
        idp.delete_user_pool(UserPoolId=pool_id)
    except idp.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
