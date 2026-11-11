"""list-workload-deployment-patterns-matches-get-workload-deployment-pattern."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-workload-deployment-patterns-matches-get-workload-deployment-pattern"
GROUP = "consistency"
SERVICES = ["launch-wizard"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The summary returned by ListWorkloadDeploymentPatterns for a given workload/pattern
    agrees on displayName/description/status/accountConstraints with the detailed record
    returned by GetWorkloadDeploymentPattern for the same pair."""
    lw = ctx.client("launch-wizard")
    workloads = lw.list_workloads(maxResults=100)["workloads"]
    active = [w for w in workloads if w["status"] == "ACTIVE"]
    assert active, "expected at least one ACTIVE workload"
    workload_name = active[0]["workloadName"]

    summaries = lw.list_workload_deployment_patterns(workloadName=workload_name, maxResults=100)[
        "workloadDeploymentPatterns"
    ]
    assert summaries, f"expected at least one deployment pattern for {workload_name!r}"
    summary = summaries[0]
    pattern_name = summary["deploymentPatternName"]

    detail = lw.get_workload_deployment_pattern(
        workloadName=workload_name, deploymentPatternName=pattern_name
    )["workloadDeploymentPattern"]

    assert detail["displayName"] == summary["displayName"], (
        f"GetWorkloadDeploymentPattern displayName {detail['displayName']!r} disagrees with "
        f"ListWorkloadDeploymentPatterns summary {summary['displayName']!r}"
    )
    assert detail["description"] == summary["description"], (
        f"GetWorkloadDeploymentPattern description {detail['description']!r} disagrees with "
        f"ListWorkloadDeploymentPatterns summary {summary['description']!r}"
    )
    assert detail["status"] == summary["status"], (
        f"GetWorkloadDeploymentPattern status {detail['status']!r} disagrees with "
        f"ListWorkloadDeploymentPatterns summary {summary['status']!r}"
    )
    assert detail.get("accountConstraints") == summary.get("accountConstraints"), (
        f"GetWorkloadDeploymentPattern accountConstraints {detail.get('accountConstraints')!r} "
        f"disagrees with ListWorkloadDeploymentPatterns summary {summary.get('accountConstraints')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
