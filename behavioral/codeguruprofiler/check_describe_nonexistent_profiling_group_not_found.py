"""describe-nonexistent-profiling-group-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-profiling-group-not-found"
GROUP = "error-semantics"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeProfilingGroup on a never-created name fails with ResourceNotFoundException and its exact message,
    while the same call on a real group returns it.
    """
    cgp = ctx.client("codeguruprofiler")
    real_name = ctx.unique_name("sim2real-cgp-real-")
    cgp.create_profiling_group(
        profilingGroupName=real_name,
        agentOrchestrationConfig={"profilingEnabled": True},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=real_name))

    described = cgp.describe_profiling_group(profilingGroupName=real_name)["profilingGroup"]
    assert described["name"] == real_name, (
        f"positive control: expected name {real_name!r}, got {described.get('name')!r}"
    )

    bogus_name = ctx.unique_name("sim2real-cgp-nosuch-")
    code, message = _error_code(lambda: cgp.describe_profiling_group(profilingGroupName=bogus_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {code}"
    )
    expected_message = (
        f"CodeGuru Profiler can\u2019t complete the operation because {bogus_name} was not found."
    )
    assert message == expected_message, (message, expected_message)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
