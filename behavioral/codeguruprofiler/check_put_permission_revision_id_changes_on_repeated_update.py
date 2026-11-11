"""put-permission-revision-id-changes-on-repeated-update."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-permission-revision-id-changes-on-repeated-update"
GROUP = "permissions"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each successful PutPermission call bumps revisionId to a new UUID and the
    policy document grows to include the newly added principal."""
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    # Two distinct, real, currently-existing IAM principals (account root and the
    # caller's own ARN) so the service's principal-existence validation accepts them.
    p1 = f"arn:aws:iam::{account_id}:root"
    p2 = sts.get_caller_identity()["Arn"]

    first = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[p1]
    )
    second = cgp.put_permission(
        profilingGroupName=name,
        actionGroup="agentPermissions",
        principals=[p1, p2],
        revisionId=first["revisionId"],
    )
    ctx.on_cleanup(
        lambda: cgp.remove_permission(
            profilingGroupName=name,
            actionGroup="agentPermissions",
            revisionId=cgp.get_policy(profilingGroupName=name)["revisionId"],
        )
    )

    assert first["revisionId"] != second["revisionId"], (
        f"expected a new revisionId after the second PutPermission, "
        f"got the same value twice: {first['revisionId']!r}"
    )
    assert p1 in second["policy"] and p2 in second["policy"], (
        f"expected both principals {p1!r} and {p2!r} in the PutPermission response "
        f"policy, got: {second['policy']!r}"
    )

    got = cgp.get_policy(profilingGroupName=name)
    assert got["revisionId"] == second["revisionId"], (
        f"expected GetPolicy's independent read to reflect revisionId "
        f"{second['revisionId']!r}, got {got['revisionId']!r}"
    )
    assert p2 in got["policy"], (
        f"expected principal {p2!r} in GetPolicy's independently-read policy, "
        f"got: {got['policy']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
