"""create-deployment-invalid-specifications-map-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-deployment-invalid-specifications-map-rejected"
GROUP = "overly-permissive"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeployment with a specifications key the deployment pattern does not define is rejected with
    ValidationException, creates no deployment, and GetWorkloadDeploymentPattern still reads the pattern."""
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

    deployment_name = ctx.unique_name("sim2real-lw-")
    code, message = _client_error(
        lambda: lw.create_deployment(
            workloadName=workload_name,
            deploymentPatternName=pattern_name,
            name=deployment_name,
            specifications={"Sim2RealUnknownSpecificationKey123": "bogus-value"},
        )
    )
    # The message's tail lists every specification the catalog pattern requires, and the pattern
    # is whichever ACTIVE workload ListWorkloads returns first, so only the leading part is stable.
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_prefix = (
        "Specification Sim2RealUnknownSpecificationKey123 is not allowed., The value of 'deploymentName' doesn't match the "
        "regular expression pattern <'^[a-zA-Z][a-zA-Z0-9]+$'>., "
    )
    assert (message or "").startswith(expected_prefix), f"expected a message starting {expected_prefix!r}, got {message!r}"

    # effect absent: no deployment was created under this name
    listed = lw.list_deployments(
        filters=[{"name": "WORKLOAD_NAME", "values": [workload_name]}], maxResults=100
    )["deployments"]
    assert all(d["name"] != deployment_name for d in listed), (
        "a deployment was created despite an invalid specifications map"
    )

    # positive control: a real read against the same workload/pattern still succeeds
    resp = lw.get_workload_deployment_pattern(
        workloadName=workload_name, deploymentPatternName=pattern_name
    )
    wdp = resp["workloadDeploymentPattern"]
    assert wdp["workloadName"] == workload_name and wdp["deploymentPatternName"] == pattern_name, (
        f"expected a read for {workload_name!r}/{pattern_name!r}, got {wdp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
