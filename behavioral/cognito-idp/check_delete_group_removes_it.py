"""delete-group-removes-it."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-group-removes-it"
GROUP = 'group-lifecycle'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGroup makes the group disappear from an independent GetGroup, a mutation
    (UpdateGroup) on the now-dead GroupName is rejected the same way, and the freed
    GroupName is reusable by CreateGroup."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    name = ctx.unique_name("sim2real-behav-cip-group-")
    c.create_group(UserPoolId=pool_id, GroupName=name)
    ctx.on_cleanup(lambda _p=pool_id, _g=name: c.delete_group(UserPoolId=_p, GroupName=_g))

    # positive control: the group is readable before delete
    pre = c.get_group(UserPoolId=pool_id, GroupName=name)["Group"]
    assert pre["GroupName"] == name, f"expected pre-delete GetGroup to return {name}, got {pre}"

    c.delete_group(UserPoolId=pool_id, GroupName=name)

    code, message = _error(lambda: c.get_group(UserPoolId=pool_id, GroupName=name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetGroup after delete, got {code}"
    )
    expected_message = "Group not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # a mutation on the dead id is rejected the same way, not silently accepted
    update_code, update_message = _error(
        lambda: c.update_group(UserPoolId=pool_id, GroupName=name, Precedence=1)
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from UpdateGroup on a deleted group, got {update_code}"
    )
    expected_update_message = "Group not found."
    assert update_message == expected_update_message, f"expected message {expected_update_message!r}, got {update_message!r}"

    # the freed GroupName is reusable
    c.create_group(UserPoolId=pool_id, GroupName=name)
    reused = c.get_group(UserPoolId=pool_id, GroupName=name)["Group"]
    assert reused["GroupName"] == name, f"expected {name} to be recreatable after delete, got {reused}"


def _error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
