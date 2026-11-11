"""op-contract-remove-user-from-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-remove-user-from-group"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveUserFromGroup detaches membership; removing a user that never existed is rejected."""
    iam = ctx.client("iam")
    group_name = ctx.unique_name("sim2real-group-")
    user_name = ctx.unique_name("sim2real-user-")

    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))

    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    iam.add_user_to_group(GroupName=group_name, UserName=user_name)
    before = iam.get_group(GroupName=group_name)
    before_names = [u["UserName"] for u in before["Users"]]
    assert before_names == [user_name], f"expected only {user_name!r} in the group, got {before_names}"

    iam.remove_user_from_group(GroupName=group_name, UserName=user_name)
    after = iam.get_group(GroupName=group_name)
    assert after["Users"] == [], f"expected no members left in the group, got {after['Users']}"

    # Removing an already-detached user from a group that still exists is a no-op, not an
    # error, as long as the user and group both still exist.
    iam.remove_user_from_group(GroupName=group_name, UserName=user_name)
    idempotent = iam.get_group(GroupName=group_name)
    assert idempotent["Users"] == [], (
        f"expected the already-detached user's second removal to stay a no-op, got {idempotent['Users']}"
    )

    # Error boundary: a genuine NoSuchEntity boundary requires an entity that does not exist
    # at all, e.g. a user name that was never created.
    missing_user_name = ctx.unique_name("sim2real-missing-user-")
    code, message = _error_code(
        lambda: iam.remove_user_from_group(GroupName=group_name, UserName=missing_user_name)
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The user with name {missing_user_name} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected NoSuchEntity, but the call succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
