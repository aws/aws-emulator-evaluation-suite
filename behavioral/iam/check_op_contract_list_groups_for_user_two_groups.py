"""op-contract-listGroupsForUser-two-groups."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listGroupsForUser-two-groups"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGroupsForUser lists exactly the user's two groups, reflects a removal, and rejects a
    missing user with NoSuchEntity and the exact message.

    Reference: https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListGroupsForUser.html
    """
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-batch09-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    group_a = ctx.unique_name("sim2real-batch09-grp-a-")
    group_b = ctx.unique_name("sim2real-batch09-grp-b-")
    iam.create_group(GroupName=group_a)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_a))
    iam.create_group(GroupName=group_b)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_b))

    iam.add_user_to_group(GroupName=group_a, UserName=user_name)
    iam.add_user_to_group(GroupName=group_b, UserName=user_name)
    ctx.on_cleanup(lambda: iam.remove_user_from_group(GroupName=group_b, UserName=user_name))

    resp = iam.list_groups_for_user(UserName=user_name)
    names = {g["GroupName"] for g in resp["Groups"]}
    assert names == {group_a, group_b}, f"expected exactly {{group_a, group_b}}, got {names}"

    iam.remove_user_from_group(GroupName=group_a, UserName=user_name)
    resp_after_removal = iam.list_groups_for_user(UserName=user_name)
    names_after_removal = {g["GroupName"] for g in resp_after_removal["Groups"]}
    assert names_after_removal == {group_b}, (
        f"expected exactly {{group_b}} after removing {user_name} from {group_a}, "
        f"got {names_after_removal}"
    )

    bogus_user = ctx.unique_name("sim2real-batch09-missing-user-")
    code, message = _error(lambda: iam.list_groups_for_user(UserName=bogus_user))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The user with name {bogus_user} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
