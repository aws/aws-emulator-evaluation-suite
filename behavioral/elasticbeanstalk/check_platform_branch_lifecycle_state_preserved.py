"""platform-branch-lifecycle-state-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "platform-branch-lifecycle-state-preserved"
GROUP = "representation"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """LifecycleState and BranchName reported by ListPlatformBranches exactly match the branch
    metadata attached to a concrete platform version returned by ListPlatformVersions -- no
    truncation or case normalization between the two APIs."""
    eb = ctx.client("elasticbeanstalk")

    versions = eb.list_platform_versions(MaxRecords=20).get("PlatformSummaryList", [])
    assert versions, "ListPlatformVersions returned no platform versions at all"

    candidate = next(
        (v for v in versions if v.get("PlatformBranchName") and v.get("PlatformBranchLifecycleState")),
        None,
    )
    assert candidate is not None, "no platform version carried both PlatformBranchName and lifecycle state"

    branch_name = candidate["PlatformBranchName"]
    expected_state = candidate["PlatformBranchLifecycleState"]

    branches = eb.list_platform_branches(
        Filters=[{"Attribute": "BranchName", "Operator": "=", "Values": [branch_name]}],
        MaxRecords=20,
    ).get("PlatformBranchSummaryList", [])
    assert branches, f"ListPlatformBranches returned nothing for branch {branch_name!r}"

    match = next((b for b in branches if b["BranchName"] == branch_name), None)
    assert match is not None, (
        f"ListPlatformBranches did not return an exact (case/whitespace-preserving) match for "
        f"BranchName={branch_name!r}, got {[b['BranchName'] for b in branches]}"
    )
    assert match["LifecycleState"] == expected_state, (
        f"branch {branch_name!r} reports LifecycleState={match['LifecycleState']!r} via ListPlatformBranches "
        f"but {expected_state!r} via ListPlatformVersions -- representations disagree"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
