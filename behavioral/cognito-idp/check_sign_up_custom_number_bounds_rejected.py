"""sign-up-custom-number-bounds-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sign-up-custom-number-bounds-rejected"
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
    """SignUp refuses a custom number above MaxValue, below MinValue and not a number, each with its
    schema message and no user; values exactly at both bounds sign up and are stored as sent.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-bounds-"),
        Schema=[{
            "Name": "score", "AttributeDataType": "Number", "Mutable": True,
            "NumberAttributeConstraints": {"MinValue": "1", "MaxValue": "10"},
        }],
        UserPoolTags={"sim2real": GROUP},
    )["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool(UserPoolId=pool_id), "ResourceNotFoundException"))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-app-"),
    )["UserPoolClient"]["ClientId"]

    def sign_up(username: str, value: str):
        return c.sign_up(
            ClientId=client_id, Username=username, Password=PASSWORD,
            UserAttributes=[{"Name": "custom:score", "Value": value}],
        )

    schema = "Attributes did not conform to the schema: "
    prefix = schema + "Custom.User.score: This attribute does not satisfy the "
    cases = [
        ("11", prefix + "MAX_VALUE_VALIDATION validation defined in the schema."),
        ("0", prefix + "MIN_VALUE_VALIDATION validation defined in the schema."),
        ("abc", schema + "1 validation error detected: Value at 'Custom.User.score' failed to "
                "satisfy constraint: Member must satisfy regular expression pattern: "
                r"$|^[+-]?((\p{Nd}+(\.\p{Nd}*)?)|(\.\p{Nd}+))([eE][+-]?\p{Nd}+)?"),
    ]
    for value, message in cases:
        username = ctx.unique_name("sim2real-behav-cip-user-")
        err = _error(lambda: sign_up(username, value))
        assert (err["Code"], err["Message"]) == ("InvalidParameterException", message), (
            f"SignUp with custom:score {value!r} answered {err!r}"
        )
        gone = _error(lambda: c.admin_get_user(UserPoolId=pool_id, Username=username))
        assert (gone["Code"], gone["Message"]) == ("UserNotFoundException", "User does not exist."), (
            f"a refused SignUp (custom:score {value!r}) left a user behind: {gone!r}"
        )

    # Legal neighbours: exactly MaxValue and exactly MinValue are accepted and stored as sent.
    for value in ("10", "1"):
        username = ctx.unique_name("sim2real-behav-cip-user-")
        out = sign_up(username, value)
        assert out["UserConfirmed"] is False, f"UserConfirmed was {out['UserConfirmed']!r}"
        attrs = {a["Name"]: a["Value"] for a in c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]}
        assert attrs.get("custom:score") == value, (
            f"custom:score stored as {attrs.get('custom:score')!r}, expected {value!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
