"""list-platform-branches-reflects-lifecycle-state."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-platform-branches-reflects-lifecycle-state"
GROUP = "state-machine"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPlatformBranches reports a LifecycleState for every AWS-managed branch, and filtering by
    that state returns exactly the branches in it."""
    ctx.client("elasticbeanstalk")

    # Custom platforms are retired, so the AWS-managed branches present in every region are used.
    all_branches = _list_all_branches(ctx, filters=None)
    assert all_branches, "expected at least one AWS-managed platform branch to be listed"
    for b in all_branches:
        assert b.get("LifecycleState"), f"branch {b.get('BranchName')} missing LifecycleState"

    state_counts: dict[str, int] = {}
    for b in all_branches:
        state_counts[b["LifecycleState"]] = state_counts.get(b["LifecycleState"], 0) + 1

    # Prefer "Supported" since it is virtually guaranteed to be non-empty; fall back to
    # whichever state is actually present.
    target_state = "Supported" if "Supported" in state_counts else next(iter(state_counts))
    expected_names = {b["BranchName"] for b in all_branches if b["LifecycleState"] == target_state}

    filtered_branches = _list_all_branches(
        ctx, filters=[{"Attribute": "LifecycleState", "Operator": "=", "Values": [target_state]}]
    )
    filtered_names = {b["BranchName"] for b in filtered_branches}

    assert filtered_names == expected_names, (
        f"LifecycleState={target_state} filter returned {filtered_names}, expected {expected_names}"
    )
    for b in filtered_branches:
        assert b["LifecycleState"] == target_state, (
            f"branch {b.get('BranchName')} returned by LifecycleState={target_state!r} filter "
            f"reports its own LifecycleState as {b['LifecycleState']!r}"
        )



def _list_all_branches(ctx, filters):
    eb = ctx.client("elasticbeanstalk")
    branches = []
    kwargs = {}
    if filters is not None:
        kwargs["Filters"] = filters
    next_token = None
    while True:
        if next_token:
            kwargs["NextToken"] = next_token
        resp = eb.list_platform_branches(**kwargs)
        branches.extend(resp.get("PlatformBranchSummaryList", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return branches


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
