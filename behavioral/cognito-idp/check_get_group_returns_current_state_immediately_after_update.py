"""get-group-returns-current-state-immediately-after-update."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-group-returns-current-state-immediately-after-update"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGroup returns the just-updated description and precedence immediately
    after UpdateGroup, with no caching lag."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    group_name = ctx.unique_name("sim2real-group-")

    idp.create_group(UserPoolId=pool_id, GroupName=group_name, Description="initial-desc", Precedence=5)

    idp.update_group(UserPoolId=pool_id, GroupName=group_name, Description="updated-desc", Precedence=99)

    group = idp.get_group(UserPoolId=pool_id, GroupName=group_name)["Group"]
    assert group["Description"] == "updated-desc", (
        f"expected Description 'updated-desc', got {group.get('Description')!r}"
    )
    assert group["Precedence"] == 99, (
        f"expected Precedence 99, got {group.get('Precedence')!r}"
    )


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    resp = idp.create_user_pool(
        PoolName=name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-"},
        **kwargs,
    )
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
