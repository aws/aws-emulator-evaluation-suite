"""get-workload-deployment-pattern-returns-specification-schema."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-workload-deployment-pattern-returns-specification-schema"
GROUP = "discovery"
SERVICES = ["launch-wizard"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetWorkloadDeploymentPattern exposes the specification schema (the input contract
    CreateDeployment validates `specifications` against) for a real workload/pattern pair,
    with every field carrying a name and a required flag drawn from {true, false}."""
    lw = ctx.client("launch-wizard")
    workloads = lw.list_workloads(maxResults=100)["workloads"]
    active = [w for w in workloads if w["status"] == "ACTIVE"]
    assert active, "expected at least one ACTIVE workload"
    workload_name = active[0]["workloadName"]

    patterns = lw.list_workload_deployment_patterns(workloadName=workload_name, maxResults=100)[
        "workloadDeploymentPatterns"
    ]
    assert patterns, f"expected at least one deployment pattern for {workload_name!r}"
    pattern_name = patterns[0]["deploymentPatternName"]

    resp = lw.get_workload_deployment_pattern(
        workloadName=workload_name, deploymentPatternName=pattern_name
    )
    wdp = resp["workloadDeploymentPattern"]
    assert wdp["workloadName"] == workload_name, (
        f"expected workloadName {workload_name!r}, got {wdp['workloadName']!r}"
    )
    assert wdp["deploymentPatternName"] == pattern_name, (
        f"expected deploymentPatternName {pattern_name!r}, got {wdp['deploymentPatternName']!r}"
    )

    specs = wdp.get("specifications", [])
    assert len(specs) > 0, "expected a non-empty specification schema"
    for field in specs:
        assert isinstance(field.get("name"), str) and field["name"], "specification field must have a name"
        if "required" in field:
            assert field["required"].strip().lower() in ("true", "false", "yes", "no"), (
                f"unexpected required flag {field['required']!r} on spec field {field['name']!r}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
