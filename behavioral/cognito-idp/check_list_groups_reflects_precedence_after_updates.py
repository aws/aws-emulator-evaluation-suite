"""list-groups-reflects-precedence-after-updates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-groups-reflects-precedence-after-updates"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After creating groups and updating their precedence, ListGroups reflects
    the current precedence values rather than the values set at creation time."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)

    names = [ctx.unique_name(f"sim2real-group-{i}-") for i in range(3)]
    initial_precedence = {names[0]: 10, names[1]: 20, names[2]: 30}
    for name, precedence in initial_precedence.items():
        idp.create_group(UserPoolId=pool_id, GroupName=name, Precedence=precedence)

    # Shuffle precedence values so none keeps its original value.
    updated_precedence = {names[0]: 30, names[1]: 10, names[2]: 20}
    for name, precedence in updated_precedence.items():
        idp.update_group(UserPoolId=pool_id, GroupName=name, Precedence=precedence)

    listed = idp.list_groups(UserPoolId=pool_id)["Groups"]
    listed_precedence = {g["GroupName"]: g["Precedence"] for g in listed if g["GroupName"] in names}

    assert listed_precedence == updated_precedence, (
        f"expected ListGroups to reflect updated precedence {updated_precedence}, "
        f"got {listed_precedence}"
    )
    assert listed_precedence != initial_precedence, (
        f"ListGroups still reflects the creation-time precedence {initial_precedence} "
        "after every group's precedence was updated"
    )


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    kwargs.setdefault("UserPoolTags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})
    resp = idp.create_user_pool(PoolName=name, **kwargs)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
