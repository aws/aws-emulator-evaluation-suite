"""deploy-create-deployment-unknown-workload-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deploy-create-deployment-unknown-workload-not-found"
GROUP = "error-semantics"
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
    """CreateDeployment for an unknown workload gets ResourceNotFoundException with its exact message and
    creates no deployment; the same call for a real workload and pattern gets ValidationException instead."""
    lw = ctx.client("launch-wizard")
    bogus_workload = "Sim2RealNoSuchWorkloadXyz"
    deployment_name = ctx.unique_name("sim2real-lw-")
    specifications = {"Placeholder": "value"}

    code, message = _client_error(
        lambda: lw.create_deployment(
            workloadName=bogus_workload,
            deploymentPatternName="bogusPattern1",
            name=deployment_name,
            specifications=specifications,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "The specified workload does not exist or insufficient permissions.", (
        f"got message={message!r}"
    )

    # effect absent: no deployment was actually created under this name
    listed = lw.list_deployments(maxResults=100)["deployments"]
    assert all(d["name"] != deployment_name for d in listed), (
        "a deployment was created despite the referenced workload not existing"
    )

    # contrast control: same call, real workload + real pattern, identical (still-bogus)
    # specifications map -- must fail differently, proving the workload lookup (not a
    # blanket CreateDeployment failure) is what produced ResourceNotFoundException above
    workloads = lw.list_workloads(maxResults=100)["workloads"]
    active = [w for w in workloads if w["status"] == "ACTIVE"]
    assert active, "expected at least one ACTIVE workload"
    real_workload_name = active[0]["workloadName"]

    patterns = lw.list_workload_deployment_patterns(workloadName=real_workload_name, maxResults=100)[
        "workloadDeploymentPatterns"
    ]
    assert patterns, f"expected at least one deployment pattern for {real_workload_name!r}"
    real_pattern_name = patterns[0]["deploymentPatternName"]

    control_deployment_name = ctx.unique_name("sim2real-lw-ctrl-")
    control_code, control_message = _client_error(
        lambda: lw.create_deployment(
            workloadName=real_workload_name,
            deploymentPatternName=real_pattern_name,
            name=control_deployment_name,
            specifications=specifications,
        )
    )
    # message varies: the text lists every specification the catalog pattern requires, and the
    # pattern is whichever ACTIVE workload ListWorkloads returns first, an order that changes per call
    assert control_code == "ValidationException", (
        f"expected ValidationException for the real workload/pattern control, got {control_code!r}"
    )
    control_listed = lw.list_deployments(maxResults=100)["deployments"]
    assert all(d["name"] != control_deployment_name for d in control_listed), (
        "a deployment was created despite an invalid specifications map"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
