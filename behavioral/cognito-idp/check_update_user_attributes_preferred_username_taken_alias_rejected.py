"""update-user-attributes-preferred-username-taken-alias-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-attributes-preferred-username-taken-alias-rejected"
GROUP = "aliases"
SERVICES = ["cognito-idp"]

PASSWORD = "Sim2Real!Passw0rd"
TAKEN = ("AliasExistsException", "User account already exists for the alias.")


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
    """A signed-in user's UpdateUserAttributes refuses a preferred_username another user holds, as
    alias or username, with AliasExistsException and no change; a free value is stored and signs in.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-alias-"),
        AliasAttributes=["preferred_username"],
        UserPoolTags={"sim2real": GROUP},
    )["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool(UserPoolId=pool_id), "ResourceNotFoundException"))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-app-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    owner = ctx.unique_name("sim2real-behav-cip-owner-")
    caller = ctx.unique_name("sim2real-behav-cip-caller-")
    owner_alias = ctx.unique_name("sim2real-behav-cip-pref-")
    c.admin_create_user(
        UserPoolId=pool_id, Username=owner, MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "preferred_username", "Value": owner_alias}],
    )
    c.admin_create_user(UserPoolId=pool_id, Username=caller, MessageAction="SUPPRESS")
    c.admin_set_user_password(UserPoolId=pool_id, Username=caller, Password=PASSWORD, Permanent=True)
    token = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": caller, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["AccessToken"]

    def set_alias(value: str):
        return c.update_user_attributes(
            AccessToken=token, UserAttributes=[{"Name": "preferred_username", "Value": value}],
        )

    def my_alias():
        attrs = {a["Name"]: a["Value"] for a in c.get_user(AccessToken=token)["UserAttributes"]}
        return attrs.get("preferred_username")

    for value in (owner_alias, owner):
        err = _error(lambda: set_alias(value))
        assert (err["Code"], err["Message"]) == TAKEN, (
            f"preferred_username held by another user answered {err!r}"
        )
        stored = my_alias()
        assert stored is None, f"a refused update set preferred_username to {stored!r}"
    assert c.admin_get_user(UserPoolId=pool_id, Username=owner_alias)["Username"] == owner, (
        "the owner's alias no longer resolves to the owner"
    )

    # Positive control: a free value is stored and the caller signs in with it.
    free = ctx.unique_name("sim2real-behav-cip-pref-")
    set_alias(free)
    stored = my_alias()
    assert stored == free, f"free alias stored as {stored!r}"
    auth = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": free, "PASSWORD": PASSWORD},
    )
    me = c.get_user(AccessToken=auth["AuthenticationResult"]["AccessToken"])
    assert me["Username"] == caller, f"signing in by the new alias returned user {me['Username']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
