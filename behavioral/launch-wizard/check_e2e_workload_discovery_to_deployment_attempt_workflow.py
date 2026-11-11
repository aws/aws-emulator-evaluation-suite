"""e2e-workload-discovery-to-deployment-attempt-workflow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-workload-discovery-to-deployment-attempt-workflow"
GROUP = "e2e"
SERVICES = ["launch-wizard"]


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The workload, pattern and version identifiers agree across the List/Get workload, pattern and version
    calls, and CreateDeployment with an incomplete specifications map for them is rejected with
    ValidationException and leaves no deployment record."""
    lw = ctx.client("launch-wizard")
    workloads = lw.list_workloads(maxResults=100)["workloads"]
    active = [w for w in workloads if w["status"] == "ACTIVE"]
    assert active, "expected at least one ACTIVE workload"
    workload_name = active[0]["workloadName"]

    workload = lw.get_workload(workloadName=workload_name)["workload"]
    assert workload["workloadName"] == workload_name, (
        f"GetWorkload returned workloadName={workload['workloadName']!r}, expected {workload_name!r}"
    )

    patterns = lw.list_workload_deployment_patterns(workloadName=workload_name, maxResults=100)[
        "workloadDeploymentPatterns"
    ]
    assert patterns, f"expected at least one deployment pattern for {workload_name!r}"
    pattern_name = patterns[0]["deploymentPatternName"]

    wdp = lw.get_workload_deployment_pattern(
        workloadName=workload_name, deploymentPatternName=pattern_name
    )["workloadDeploymentPattern"]
    assert wdp["workloadName"] == workload_name, (
        f"GetWorkloadDeploymentPattern returned workloadName={wdp['workloadName']!r}, "
        f"expected {workload_name!r}"
    )
    assert wdp["deploymentPatternName"] == pattern_name, (
        f"GetWorkloadDeploymentPattern returned deploymentPatternName={wdp['deploymentPatternName']!r}, "
        f"expected {pattern_name!r}"
    )

    versions = lw.list_deployment_pattern_versions(
        workloadName=workload_name, deploymentPatternName=pattern_name, maxResults=100
    )["deploymentPatternVersions"]
    assert versions, f"expected at least one pattern version for {workload_name}/{pattern_name}"
    version_summary = versions[0]
    version_name = version_summary["deploymentPatternVersionName"]

    got = lw.get_deployment_pattern_version(
        workloadName=workload_name,
        deploymentPatternName=pattern_name,
        deploymentPatternVersionName=version_name,
    )["deploymentPatternVersion"]

    assert got["deploymentPatternVersionName"] == version_name, (
        f"GetDeploymentPatternVersion returned deploymentPatternVersionName="
        f"{got['deploymentPatternVersionName']!r}, expected {version_name!r}"
    )
    assert got["workloadName"] == workload_name, (
        f"GetDeploymentPatternVersion returned workloadName={got['workloadName']!r}, "
        f"expected {workload_name!r}"
    )
    assert got["deploymentPatternName"] == pattern_name, (
        f"GetDeploymentPatternVersion returned deploymentPatternName={got['deploymentPatternName']!r}, "
        f"expected {pattern_name!r}"
    )
    assert got.get("description") == version_summary.get("description"), (
        f"GetDeploymentPatternVersion description={got.get('description')!r} disagrees with "
        f"ListDeploymentPatternVersions summary description={version_summary.get('description')!r}"
    )

    # exercise CreateDeployment on the exact workload/pattern this workflow discovered, with
    # a deliberately incomplete specifications map -- it fails validation (not resource
    # lookup, since workload/pattern are real) and provisions nothing.
    deployment_name = ctx.unique_name("sim2real-lw-e2e-")
    code, message = _client_error(
        lambda: lw.create_deployment(
            workloadName=workload_name,
            deploymentPatternName=pattern_name,
            name=deployment_name,
            specifications={"Sim2RealIncompleteSpec": "x"},
        )
    )
    # The message's tail lists every specification the catalog pattern requires, and the pattern
    # is whichever ACTIVE workload ListWorkloads returns first, so only the leading part is stable.
    assert code == "ValidationException", (
        f"expected ValidationException from an incomplete spec against the real "
        f"workload/pattern this workflow discovered, got {code!r}"
    )
    expected_prefix = (
        "Specification Sim2RealIncompleteSpec is not allowed., The value of 'deploymentName' doesn't match the "
        "regular expression pattern <'^[a-zA-Z][a-zA-Z0-9]+$'>., "
    )
    assert (message or "").startswith(expected_prefix), f"expected a message starting {expected_prefix!r}, got {message!r}"

    listed = lw.list_deployments(
        filters=[{"name": "WORKLOAD_NAME", "values": [workload_name]}], maxResults=100
    )["deployments"]
    assert all(d["name"] != deployment_name for d in listed), (
        "the end-to-end workflow's rejected CreateDeployment still left a deployment record"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
