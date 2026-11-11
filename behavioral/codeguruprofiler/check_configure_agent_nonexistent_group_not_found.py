"""configure-agent-nonexistent-group-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configure-agent-nonexistent-group-not-found"
GROUP = "error-semantics"
SERVICES = ["codeguruprofiler"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConfigureAgent succeeds on a real profiling group and fails on an unknown name with
    ResourceNotFoundException and its exact message, and DescribeProfilingGroup on that name also fails
    not-found, so no group was created.
    """
    cgp = ctx.client("codeguruprofiler")
    real_name = ctx.unique_name("sim2real-cgp-real-")
    cgp.create_profiling_group(
        profilingGroupName=real_name,
        clientToken=str(uuid.uuid4()),
        tags={"env": "test", "owner": "sim2real"},
        agentOrchestrationConfig={"profilingEnabled": True},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=real_name))

    configuration = cgp.configure_agent(profilingGroupName=real_name)["configuration"]
    assert configuration["shouldProfile"] is True, (
        f"positive control did not enable profiling: {configuration!r}"
    )
    assert isinstance(configuration["periodInSeconds"], int) and configuration["periodInSeconds"] > 0, (
        f"positive control returned a non-positive period: {configuration!r}"
    )

    missing_name = ctx.unique_name("sim2real-cgp-noagent-")
    error = _client_error(lambda: cgp.configure_agent(profilingGroupName=missing_name))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"ConfigureAgent on a nonexistent group returned {error.get('Code')!r}, expected "
        f"'ResourceNotFoundException'"
    )
    expected_message = f"Profiling group for {ctx.account}/{missing_name} does not exist!"
    assert error.get("Message") == expected_message, (error.get("Message"), expected_message)

    describe_error = _client_error(
        lambda: cgp.describe_profiling_group(profilingGroupName=missing_name)
    )
    assert describe_error.get("Code") == "ResourceNotFoundException", (
        f"the rejected ConfigureAgent call left something describable: "
        f"DescribeProfilingGroup returned {describe_error.get('Code')!r} instead of "
        f"'ResourceNotFoundException'"
    )
    expected_describe_message = (
        f"CodeGuru Profiler can\u2019t complete the operation because {missing_name} was not found."
    )
    assert describe_error.get("Message") == expected_describe_message, (
        describe_error.get("Message"),
        expected_describe_message,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
