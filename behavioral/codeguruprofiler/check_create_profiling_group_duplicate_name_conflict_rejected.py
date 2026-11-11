"""create-profiling-group-duplicate-name-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-profiling-group-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProfilingGroup with an existing name and a fresh clientToken fails with ConflictException and its
    exact message, leaving the existing group's config and createdAt unchanged, while a different name is
    created.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    original = cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
    )["profilingGroup"]
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    code, message = _error_code(
        lambda: cgp.create_profiling_group(
            profilingGroupName=name,
            agentOrchestrationConfig={"profilingEnabled": False},
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = f"ProfilingGroup (name: {name}, accountId: {ctx.account}) already exists."
    assert message == expected_message, (message, expected_message)

    # Effect absent: the original group's config/creation time is untouched.
    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert described["agentOrchestrationConfig"]["profilingEnabled"] is True, (
        "rejected duplicate create must not flip profilingEnabled on the original group: "
        f"got {described['agentOrchestrationConfig']!r}"
    )
    assert described["createdAt"] == original["createdAt"], (
        f"expected createdAt {original['createdAt']!r} unchanged, got {described['createdAt']!r}"
    )

    # Positive control: creating a group under a different, unused name succeeds.
    other_name = ctx.unique_name("sim2real-behav-cgp-")
    other = cgp.create_profiling_group(
        profilingGroupName=other_name,
        agentOrchestrationConfig={"profilingEnabled": True},
    )["profilingGroup"]
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=other_name))
    assert other["name"] == other_name, (
        f"expected create under fresh name {other_name!r} to succeed, got {other['name']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
