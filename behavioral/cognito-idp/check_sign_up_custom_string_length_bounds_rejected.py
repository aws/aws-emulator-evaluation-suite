"""sign-up-custom-string-length-bounds-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sign-up-custom-string-length-bounds-rejected"
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
    """SignUp refuses a custom string one past MaxLength and one short of MinLength with the schema
    message for each bound and creates no user; values exactly at both bounds sign up and are stored.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-bounds-"),
        Schema=[{
            "Name": "tier", "AttributeDataType": "String", "Mutable": True,
            "StringAttributeConstraints": {"MinLength": "2", "MaxLength": "5"},
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
            UserAttributes=[{"Name": "custom:tier", "Value": value}],
        )

    prefix = "Attributes did not conform to the schema: Custom.User.tier: This attribute does not satisfy the "
    cases = [
        ("abcdef", prefix + "MAX_LENGTH_VALIDATION validation defined in the schema."),
        ("a", prefix + "MIN_LENGTH_VALIDATION validation defined in the schema."),
    ]
    for value, message in cases:
        username = ctx.unique_name("sim2real-behav-cip-user-")
        err = _error(lambda: sign_up(username, value))
        assert (err["Code"], err["Message"]) == ("InvalidParameterException", message), (
            f"SignUp with custom:tier of length {len(value)} answered {err!r}"
        )
        gone = _error(lambda: c.admin_get_user(UserPoolId=pool_id, Username=username))
        assert (gone["Code"], gone["Message"]) == ("UserNotFoundException", "User does not exist."), (
            f"a refused SignUp (length {len(value)}) left a user behind: {gone!r}"
        )

    # Legal neighbours: exactly MaxLength and exactly MinLength are accepted and stored as sent.
    for value in ("abcde", "ab"):
        username = ctx.unique_name("sim2real-behav-cip-user-")
        out = sign_up(username, value)
        assert out["UserConfirmed"] is False, f"UserConfirmed was {out['UserConfirmed']!r}"
        attrs = {a["Name"]: a["Value"] for a in c.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]}
        assert attrs.get("custom:tier") == value, (
            f"custom:tier stored as {attrs.get('custom:tier')!r}, expected {value!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
