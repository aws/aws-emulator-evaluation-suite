"""list-workload-deployment-patterns-for-known-workload."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "list-workload-deployment-patterns-for-known-workload"
GROUP = "discovery"
SERVICES = ["launch-wizard"]

_PATTERN_NAME_RE = re.compile(r"^[A-Za-z0-9][a-zA-Z0-9-]*$")
_VALID_STATUSES = {"ACTIVE", "INACTIVE", "DISABLED", "DELETED"}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListWorkloadDeploymentPatterns returns at least one well-formed deployment pattern
    for a real, currently-ACTIVE workload."""
    lw = ctx.client("launch-wizard")
    workloads = lw.list_workloads(maxResults=100)["workloads"]
    active = [w for w in workloads if w["status"] == "ACTIVE"]
    assert active, "expected at least one ACTIVE workload to probe patterns for"
    workload_name = active[0]["workloadName"]

    resp = lw.list_workload_deployment_patterns(workloadName=workload_name, maxResults=100)
    patterns = resp.get("workloadDeploymentPatterns", [])
    assert len(patterns) > 0, f"expected at least one deployment pattern for workload {workload_name!r}"

    for p in patterns:
        assert p["workloadName"] == workload_name, (
            f"expected pattern workloadName {workload_name!r}, got {p['workloadName']!r}"
        )
        assert _PATTERN_NAME_RE.match(p["deploymentPatternName"]), (
            f"deploymentPatternName {p['deploymentPatternName']!r} violates naming pattern"
        )
        assert p["status"] in _VALID_STATUSES, (
            f"unexpected deployment pattern status {p['status']!r} for {p['deploymentPatternName']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
