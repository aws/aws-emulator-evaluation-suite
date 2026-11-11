"""update-profiling-group-nonexistent-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-profiling-group-nonexistent-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["codeguruprofiler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateProfilingGroup against a profiling group name that was never created is
    rejected with ResourceNotFoundException, while UpdateProfilingGroup against a real,
    existing profiling group (positive control) succeeds and persists the change."""
    cgp = ctx.client("codeguruprofiler")
    missing_name = ctx.unique_name("sim2real-cgp-missing-")
    real_name = ctx.unique_name("sim2real-cgp-real-")
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=real_name))

    code, message = _error_code(
        lambda: cgp.update_profiling_group(
            profilingGroupName=missing_name,
            agentOrchestrationConfig={"profilingEnabled": False},
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = (
        f"Unable to find profiling group with accountId: {ctx.account}; "
        f"profilingGroupName: {missing_name} during update"
    )
    assert message == expected_message, (message, expected_message)

    cgp.create_profiling_group(
        profilingGroupName=real_name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "sim2real"},
    )
    updated = cgp.update_profiling_group(
        profilingGroupName=real_name, agentOrchestrationConfig={"profilingEnabled": False}
    )["profilingGroup"]
    assert updated["agentOrchestrationConfig"]["profilingEnabled"] is False, (
        "UpdateProfilingGroup's own response did not reflect profilingEnabled=False"
    )

    described = cgp.describe_profiling_group(profilingGroupName=real_name)["profilingGroup"]
    assert described["agentOrchestrationConfig"]["profilingEnabled"] is False, (
        f"DescribeProfilingGroup (independent read) still reports "
        f"profilingEnabled={described['agentOrchestrationConfig']['profilingEnabled']} "
        "after UpdateProfilingGroup set it False"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
