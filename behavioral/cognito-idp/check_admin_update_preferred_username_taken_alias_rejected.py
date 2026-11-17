"""admin-update-preferred-username-taken-alias-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-update-preferred-username-taken-alias-rejected"
GROUP = "aliases"
SERVICES = ["cognito-idp"]

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
    """AdminUpdateUserAttributes refuses a preferred_username equal to another user's alias or
    username with AliasExistsException and changes nothing; the user's own username and a free value pass.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-alias-"),
        AliasAttributes=["preferred_username"],
        UserPoolTags={"sim2real": GROUP},
    )["UserPool"]["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_user_pool(UserPoolId=pool_id), "ResourceNotFoundException"))

    owner = ctx.unique_name("sim2real-behav-cip-owner-")
    other = ctx.unique_name("sim2real-behav-cip-other-")
    owner_alias = ctx.unique_name("sim2real-behav-cip-pref-")
    for name in (owner, other):
        c.admin_create_user(UserPoolId=pool_id, Username=name, MessageAction="SUPPRESS")

    def set_alias(username: str, value: str):
        return c.admin_update_user_attributes(
            UserPoolId=pool_id, Username=username,
            UserAttributes=[{"Name": "preferred_username", "Value": value}],
        )

    def alias_of(username: str):
        user = c.admin_get_user(UserPoolId=pool_id, Username=username)
        return {a["Name"]: a["Value"] for a in user["UserAttributes"]}.get("preferred_username")

    set_alias(owner, owner_alias)

    for value in (owner_alias, owner):
        err = _error(lambda: set_alias(other, value))
        assert (err["Code"], err["Message"]) == TAKEN, (
            f"preferred_username taken by another user ({'alias' if value == owner_alias else 'username'}) "
            f"answered {err!r}"
        )
        stored = alias_of(other)
        assert stored is None, f"a refused update set preferred_username to {stored!r}"

    # The owner keeps the alias: it still resolves to the owner, not the refused caller.
    assert c.admin_get_user(UserPoolId=pool_id, Username=owner_alias)["Username"] == owner, (
        "the owner's alias no longer resolves to the owner"
    )

    # Legal neighbours: the user's own username, then a free value, are accepted.
    set_alias(other, other)
    stored = alias_of(other)
    assert stored == other, f"own-username alias stored as {stored!r}"
    free = ctx.unique_name("sim2real-behav-cip-pref-")
    set_alias(other, free)
    stored = alias_of(other)
    assert stored == free, f"free alias stored as {stored!r}"
    resolved = c.admin_get_user(UserPoolId=pool_id, Username=free)["Username"]
    assert resolved == other, f"the free alias resolved to {resolved!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
