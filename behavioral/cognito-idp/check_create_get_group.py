"""create-get-group."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "create-get-group"
GROUP = 'group-lifecycle'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGroup followed by GetGroup returns matching group metadata."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    name = ctx.unique_name("sim2real-behav-cip-group-")
    _res1 = name
    c.create_group(UserPoolId=pool_id, GroupName=_res1, Description="test group")
    ctx.on_cleanup(lambda _p=pool_id, _g=_res1: c.delete_group(UserPoolId=_p, GroupName=_g))

    got = c.get_group(UserPoolId=pool_id, GroupName=name)["Group"]
    assert got["GroupName"] == name, f"expected GroupName {name!r}, got {got.get('GroupName')!r}"
    assert got["Description"] == "test group", f"expected Description 'test group', got {got.get('Description')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
