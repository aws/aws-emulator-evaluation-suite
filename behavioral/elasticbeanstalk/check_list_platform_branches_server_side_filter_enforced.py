"""list-platform-branches-server-side-filter-enforced."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-platform-branches-server-side-filter-enforced"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPlatformBranches with a LifecycleState filter only returns branches server-side
    matching that exact state, never branches in other lifecycle states."""
    eb = ctx.client("elasticbeanstalk")

    unfiltered = eb.list_platform_branches(MaxRecords=100).get("PlatformBranchSummaryList", [])
    assert unfiltered, "ListPlatformBranches returned no branches at all; cannot validate filtering"
    states_seen = {b["LifecycleState"] for b in unfiltered}
    assert len(states_seen) > 1, (
        f"expected AWS-managed platform branches to span multiple lifecycle states, saw only {states_seen}; "
        "cannot exercise a meaningful filter"
    )

    target_state = "Retired" if "Retired" in states_seen else sorted(states_seen)[0]
    filtered = eb.list_platform_branches(
        Filters=[{"Attribute": "LifecycleState", "Operator": "=", "Values": [target_state]}],
        MaxRecords=100,
    ).get("PlatformBranchSummaryList", [])

    assert filtered, f"filtering by LifecycleState={target_state!r} returned zero branches"
    for branch in filtered:
        assert branch["LifecycleState"] == target_state, (
            f"branch {branch.get('BranchName')} has LifecycleState={branch['LifecycleState']!r}, "
            f"expected only {target_state!r} to be returned"
        )

    other_state = next(s for s in states_seen if s != target_state)
    other_filtered = eb.list_platform_branches(
        Filters=[{"Attribute": "LifecycleState", "Operator": "=", "Values": [other_state]}],
        MaxRecords=100,
    ).get("PlatformBranchSummaryList", [])
    assert other_filtered, f"filtering by LifecycleState={other_state!r} returned zero branches"
    leaked = [b for b in other_filtered if b["LifecycleState"] == target_state]
    assert not leaked, f"branches with LifecycleState={target_state!r} leaked into the {other_state!r} filter result"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
