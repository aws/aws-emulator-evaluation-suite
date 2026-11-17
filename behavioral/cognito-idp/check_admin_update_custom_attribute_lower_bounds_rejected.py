"""admin-update-custom-attribute-lower-bounds-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-update-custom-attribute-lower-bounds-rejected"
GROUP = "attribute-constraints"
SERVICES = ["cognito-idp"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> dict:
    """The ClientError ``fn`` raises as {Code, Message}. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminUpdateUserAttributes refuses a custom string under MinLength, a number under MinValue and
    a non-number, each with its exact message, leaving the stored values; the bounds themselves pass.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-bounds-"),
        Schema=[
            {"Name": "tier", "AttributeDataType": "String", "Mutable": True,
             "StringAttributeConstraints": {"MinLength": "2", "MaxLength": "5"}},
            {"Name": "score", "AttributeDataType": "Number", "Mutable": True,
             "NumberAttributeConstraints": {"MinValue": "1", "MaxValue": "10"}},
        ],
        UserPoolTags={"sim2real": GROUP},
    )["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool(UserPoolId=pool_id), "ResourceNotFoundException"))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "custom:tier", "Value": "gold"}, {"Name": "custom:score", "Value": "7"}],
    )

    def update(name: str, value: str):
        return c.admin_update_user_attributes(
            UserPoolId=pool_id, Username=username, UserAttributes=[{"Name": name, "Value": value}],
        )

    def stored() -> dict:
        user = c.admin_get_user(UserPoolId=pool_id, Username=username)
        return {a["Name"]: a["Value"] for a in user["UserAttributes"]}

    cases = [
        ("custom:tier", "a", "user.custom:tier: String must be no shorter than 2 characters\n"),
        ("custom:score", "0", "user.custom:score: Number must be greater than 1\n"),
        ("custom:score", "abc", "user.custom:score: Unable to parse the number\n"),
    ]
    for name, value, message in cases:
        err = _error(lambda: update(name, value))
        assert (err["Code"], err["Message"]) == ("InvalidParameterException", message), (
            f"AdminUpdateUserAttributes {name}={value!r} answered {err!r}"
        )
        now = stored()
        assert (now.get("custom:tier"), now.get("custom:score")) == ("gold", "7"), (
            f"a refused update of {name}={value!r} changed the stored values: "
            f"{(now.get('custom:tier'), now.get('custom:score'))!r}"
        )

    # Legal neighbours: exactly MinLength and exactly MinValue are accepted and stored.
    update("custom:tier", "ab")
    update("custom:score", "1")
    now = stored()
    assert (now.get("custom:tier"), now.get("custom:score")) == ("ab", "1"), (
        f"boundary updates stored {(now.get('custom:tier'), now.get('custom:score'))!r}, expected ('ab', '1')"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
