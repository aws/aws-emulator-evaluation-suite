"""get-sync-blocker-summary-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-sync-blocker-summary-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSyncBlockerSummary for a resource with no sync configuration succeeds with the given
    ResourceName, an empty LatestBlockers list and no ParentResourceName."""
    cc = ctx.client("codeconnections")
    resource_name = ctx.unique_name("s2rsync")[:100]

    resp = cc.get_sync_blocker_summary(ResourceName=resource_name, SyncType="CFN_STACK_SYNC")
    summary = resp["SyncBlockerSummary"]
    assert summary["ResourceName"] == resource_name, (
        f"expected echoed ResourceName {resource_name!r}, got {summary['ResourceName']!r}"
    )
    assert summary["LatestBlockers"] == [], (
        f"expected no blockers for a resource with no sync configuration, got {summary['LatestBlockers']!r}"
    )
    assert "ParentResourceName" not in summary, (
        f"expected no ParentResourceName for a non-nested resource, got {summary.get('ParentResourceName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
