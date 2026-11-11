"""admin-add-user-to-nonexistent-group-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-add-user-to-nonexistent-group-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminAddUserToGroup adds a user to a real group (HTTP 200, listed by AdminListGroupsForUser) and refuses
    an unknown group with ResourceNotFoundException 'Group not found.', leaving the membership unchanged."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))

    # Positive control: AdminAddUserToGroup must actually work against a real group, or
    # "rejects an unknown group" is indistinguishable from "rejects the call outright".
    real_group = ctx.unique_name("sim2real-behav-cip-group-")
    c.create_group(UserPoolId=pool_id, GroupName=real_group)
    ctx.on_cleanup(lambda _p=pool_id, _g=real_group: c.delete_group(UserPoolId=_p, GroupName=_g))
    status = c.admin_add_user_to_group(
        UserPoolId=pool_id, Username=username, GroupName=real_group
    )["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 from AdminAddUserToGroup, got {status}"
    before = [g["GroupName"] for g in c.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]]
    assert real_group in before, f"expected {real_group} in {before} after AdminAddUserToGroup"

    bogus_group = ctx.unique_name("sim2real-behav-cip-nogroup-")
    code, message = _error(
        lambda: c.admin_add_user_to_group(
            UserPoolId=pool_id, Username=username, GroupName=bogus_group
        )
    )
    assert (code, message) == ("ResourceNotFoundException", "Group not found."), (
        f"expected ResourceNotFoundException for unknown group, got {(code, message)!r}"
    )

    # The rejected call must not have side-effected the real membership — independent
    # terminal read, at the destination, distinct from the mutating call it verifies.
    after = [g["GroupName"] for g in c.admin_list_groups_for_user(UserPoolId=pool_id, Username=username)["Groups"]]
    assert after == before, f"membership changed after rejected call: {before} -> {after}"


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds raises: a target that
    accepts what AWS refuses must fail loudly, never as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
