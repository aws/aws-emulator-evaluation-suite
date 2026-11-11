"""admin-add-nonexistent-user-to-group-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-add-nonexistent-user-to-group-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminAddUserToGroup with an unknown user fails with UserNotFoundException and adds no
    member, while a real user is accepted; once that username exists, the identical call succeeds.
    A deleted pool then 404s on DescribeUserPool."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    # The check deletes the pool itself (with its group and users); this covers an early stop.
    ctx.on_cleanup(lambda _id=pool_id: _delete_pool_if_present(c, _id))
    group_name = ctx.unique_name("sim2real-behav-cip-group-")
    c.create_group(UserPoolId=pool_id, GroupName=group_name)

    # Positive control: the pool and group are otherwise healthy — a real user is accepted,
    # proven by an independent read (AdminListGroupsForUser, not AdminAddUserToGroup's own 200).
    control_user = ctx.unique_name("sim2real-behav-cip-control-")
    c.admin_create_user(UserPoolId=pool_id, Username=control_user, MessageAction="SUPPRESS")
    c.admin_add_user_to_group(UserPoolId=pool_id, Username=control_user, GroupName=group_name)
    control_groups = c.admin_list_groups_for_user(UserPoolId=pool_id, Username=control_user)["Groups"]
    assert group_name in [g["GroupName"] for g in control_groups], (
        f"positive control failed: expected {group_name!r} in {control_groups!r}"
    )

    # Break: a username that does not exist yet MUST be rejected.
    bogus_user = ctx.unique_name("sim2real-behav-cip-nouser-")
    code, message = _error(
        lambda: c.admin_add_user_to_group(UserPoolId=pool_id, Username=bogus_user, GroupName=group_name)
    )
    assert (code, message) == ("UserNotFoundException", "User does not exist."), (
        f"expected UserNotFoundException for unknown user, got {(code, message)!r}"
    )

    # Effect absent: the rejected call never added the bogus name, via an independent read on a
    # different operation than the one that was rejected.
    members = c.list_users_in_group(UserPoolId=pool_id, GroupName=group_name)["Users"]
    member_names = [u["Username"] for u in members]
    assert bogus_user not in member_names, (
        f"expected {bogus_user!r} absent from group members, got {member_names!r}"
    )

    # Restore: the same username, once it names a real user, is accepted by the identical call.
    c.admin_create_user(UserPoolId=pool_id, Username=bogus_user, MessageAction="SUPPRESS")
    c.admin_add_user_to_group(UserPoolId=pool_id, Username=bogus_user, GroupName=group_name)
    restored_groups = c.admin_list_groups_for_user(UserPoolId=pool_id, Username=bogus_user)["Groups"]
    assert group_name in [g["GroupName"] for g in restored_groups], (
        f"restore failed: expected {group_name!r} in {restored_groups!r} after creating the user"
    )

    # Deletes prove gone: DeleteUserPool takes effect immediately — an independent read
    # (DescribeUserPool, not the delete call's own 200) 404s right away.
    c.delete_user_pool(UserPoolId=pool_id)
    describe_code, describe_message = _error(lambda: c.describe_user_pool(UserPoolId=pool_id))
    assert (describe_code, describe_message) == ("ResourceNotFoundException", f"User pool {pool_id} does not exist."), (
        f"expected the deleted pool to 404 on DescribeUserPool, got {(describe_code, describe_message)!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds raises: a target that
    accepts what AWS refuses must fail loudly, never as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_pool_if_present(c, pool_id):
    """Teardown for a pool the check may already have deleted as one of its steps."""
    try:
        c.delete_user_pool(UserPoolId=pool_id)
    except c.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
