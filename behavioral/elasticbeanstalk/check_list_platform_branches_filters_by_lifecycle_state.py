"""list-platform-branches-filters-by-lifecycle-state."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-platform-branches-filters-by-lifecycle-state"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPlatformBranches with a LifecycleState filter returns only branches in that exact
    state, and disjoint filters (supported vs. deprecated) never overlap.
    """
    eb = ctx.client("elasticbeanstalk")

    supported = _list_branches(eb, "Supported")
    deprecated = _list_branches(eb, "Deprecated")

    assert supported, "expected at least one AWS-managed platform branch in 'Supported' state"
    assert deprecated, "expected at least one AWS-managed platform branch in 'Deprecated' state"

    for branch in supported:
        assert branch["LifecycleState"] == "Supported", (
            f"filtering by LifecycleState=Supported returned branch {branch.get('BranchName')!r} "
            f"with LifecycleState={branch['LifecycleState']!r}"
        )

    for branch in deprecated:
        assert branch["LifecycleState"] == "Deprecated", (
            f"filtering by LifecycleState=Deprecated returned branch {branch.get('BranchName')!r} "
            f"with LifecycleState={branch['LifecycleState']!r}"
        )

    supported_keys = {(b["PlatformName"], b["BranchName"]) for b in supported}
    deprecated_keys = {(b["PlatformName"], b["BranchName"]) for b in deprecated}
    overlap = supported_keys & deprecated_keys
    assert not overlap, f"the same branch appeared in both lifecycle-state filters: {overlap}"


def _list_branches(eb, lifecycle_state: str):
    branches = []
    token = None
    while True:
        kwargs = {
            "Filters": [
                {"Attribute": "LifecycleState", "Operator": "=", "Values": [lifecycle_state]}
            ]
        }
        if token:
            kwargs["NextToken"] = token
        resp = eb.list_platform_branches(**kwargs)
        branches.extend(resp.get("PlatformBranchSummaryList", []))
        token = resp.get("NextToken")
        if not token:
            break
    return branches


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
