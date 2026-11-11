"""get-workload-matches-listed-workload."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-workload-matches-listed-workload"
GROUP = "consistency"
SERVICES = ["launch-wizard"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetWorkload returns a record for a workload discovered via ListWorkloads whose
    identity/status fields agree exactly with the ListWorkloads summary."""
    lw = ctx.client("launch-wizard")
    listed = lw.list_workloads(maxResults=100)["workloads"]
    assert listed, "expected at least one workload in the catalog"
    summary = listed[0]

    got = lw.get_workload(workloadName=summary["workloadName"])["workload"]

    assert got["workloadName"] == summary["workloadName"], (
        f"expected workloadName {summary['workloadName']!r}, got {got['workloadName']!r}"
    )
    assert got["status"] == summary["status"], (
        f"expected status {summary['status']!r}, got {got['status']!r}"
    )
    assert got.get("displayName") == summary.get("displayName"), (
        f"expected displayName {summary.get('displayName')!r}, got {got.get('displayName')!r}"
    )
    assert got.get("accountConstraints") == summary.get("accountConstraints"), (
        f"expected accountConstraints {summary.get('accountConstraints')!r}, "
        f"got {got.get('accountConstraints')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
