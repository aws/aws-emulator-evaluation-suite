"""update-group-concurrent-precedence-change-conflict."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "update-group-concurrent-precedence-change-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateGroup calls changing only Precedence leave the group at one of the two
    submitted values, the same on two consecutive reads."""
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-ugp-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-ugp"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    group_name = ctx.unique_name("sim2real-ugp-grp-")
    cognito.create_group(GroupName=group_name, UserPoolId=pool_id, Precedence=1)

    candidate_a, candidate_b = 5, 9

    def _set_precedence(value):
        return cognito.update_group(
            GroupName=group_name, UserPoolId=pool_id, Precedence=value
        )

    with ThreadPoolExecutor(max_workers=2) as pool_exec:
        fut_a = pool_exec.submit(_set_precedence, candidate_a)
        fut_b = pool_exec.submit(_set_precedence, candidate_b)
        fut_a.result()
        fut_b.result()

    read_a = cognito.get_group(GroupName=group_name, UserPoolId=pool_id)["Group"]
    read_b = cognito.get_group(GroupName=group_name, UserPoolId=pool_id)["Group"]

    assert read_a["Precedence"] == read_b["Precedence"], (
        "GetGroup Precedence flapped across two immediate, unmodified reads after the race"
    )
    assert read_a["Precedence"] in (candidate_a, candidate_b), (
        f"final Precedence {read_a['Precedence']!r} is neither racer's submitted value "
        f"({candidate_a}, {candidate_b}) -- looks like a merged or corrupted write"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
