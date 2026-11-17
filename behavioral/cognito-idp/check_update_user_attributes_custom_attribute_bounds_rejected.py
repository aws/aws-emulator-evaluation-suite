"""update-user-attributes-custom-attribute-bounds-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-attributes-custom-attribute-bounds-rejected"
GROUP = "attribute-constraints"
SERVICES = ["cognito-idp"]

PASSWORD = "Sim2Real!Passw0rd"


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
    """A signed-in user's UpdateUserAttributes refuses a custom string past MaxLength and a custom
    number past MaxValue with the exact message, keeping the stored values; values exactly at each
    bound are stored.
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
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-app-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "custom:tier", "Value": "gold"}, {"Name": "custom:score", "Value": "7"}],
    )
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)
    token = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["AccessToken"]

    def update(name: str, value: str):
        return c.update_user_attributes(AccessToken=token, UserAttributes=[{"Name": name, "Value": value}])

    def stored() -> tuple:
        attrs = {a["Name"]: a["Value"] for a in c.get_user(AccessToken=token)["UserAttributes"]}
        return attrs.get("custom:tier"), attrs.get("custom:score")

    # The lower bounds and the unparsable number are refused on the AdminUpdateUserAttributes and
    # SignUp surfaces already; the self-service surface carries the upper bound per attribute type.
    cases = [
        ("custom:tier", "abcdef", "user.custom:tier: String must be no longer than 5 characters\n"),
        ("custom:score", "11", "user.custom:score: Number must be less than 10\n"),
    ]
    for name, value, message in cases:
        err = _error(lambda: update(name, value))
        assert (err["Code"], err["Message"]) == ("InvalidParameterException", message), (
            f"UpdateUserAttributes {name}={value!r} answered {err!r}"
        )
        after = stored()
        assert after == ("gold", "7"), f"a refused update of {name}={value!r} changed the stored values: {after!r}"

    # Legal neighbours: each bound itself is accepted and read back through GetUser.
    for tier, score in (("abcde", "10"), ("ab", "1")):
        update("custom:tier", tier)
        update("custom:score", score)
        after = stored()
        assert after == (tier, score), f"boundary updates stored {after!r}, expected {(tier, score)!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
