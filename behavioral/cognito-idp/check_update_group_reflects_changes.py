"""update-group-reflects-changes."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "update-group-reflects-changes"
GROUP = 'group-lifecycle'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGroup persists a changed field on a subsequent, independent GetGroup, and
    leaves a field it was NOT given (Precedence) untouched rather than clearing it."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    name = ctx.unique_name("sim2real-behav-cip-group-")
    c.create_group(UserPoolId=pool_id, GroupName=name, Description="before", Precedence=3)
    ctx.on_cleanup(lambda _p=pool_id, _g=name: c.delete_group(UserPoolId=_p, GroupName=_g))

    # Only Description is sent -- Precedence must survive untouched.
    c.update_group(UserPoolId=pool_id, GroupName=name, Description="after")
    got = c.get_group(UserPoolId=pool_id, GroupName=name)["Group"]
    assert got["Description"] == "after", (
        f"expected Description 'after', got {got['Description']}"
    )
    assert got["Precedence"] == 3, (
        f"UpdateGroup without Precedence must not touch it: expected 3, got {got.get('Precedence')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
