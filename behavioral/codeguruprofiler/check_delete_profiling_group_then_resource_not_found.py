"""delete-profiling-group-then-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-profiling-group-then-resource-not-found"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_if_present(cgp, name):
    try:
        cgp.delete_profiling_group(profilingGroupName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteProfilingGroup: DescribeProfilingGroup, GetPolicy and a mutation
    (UpdateProfilingGroup) all transition to ResourceNotFoundException for that name
    (permanent removal, not merely a stale read), and the freed name is reusable."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
    )
    # Safety net only: real deletion happens inline below.
    ctx.on_cleanup(lambda: _delete_if_present(cgp, name))

    # Sanity: group is describable before deletion.
    cgp.describe_profiling_group(profilingGroupName=name)

    cgp.delete_profiling_group(profilingGroupName=name)

    code, message = _error_code(lambda: cgp.describe_profiling_group(profilingGroupName=name))
    assert code == "ResourceNotFoundException", f"describe after delete: expected ResourceNotFoundException, got {code}"
    expected_message = f"CodeGuru Profiler can\u2019t complete the operation because {name} was not found."
    assert message == expected_message, (message, expected_message)

    code, message = _error_code(lambda: cgp.get_policy(profilingGroupName=name))
    assert code == "ResourceNotFoundException", f"get_policy after delete: expected ResourceNotFoundException, got {code}"
    expected_message = f"No profiling group with accountId: {ctx.account}; name: {name} was found."
    assert message == expected_message, (message, expected_message)

    # A mutation on the dead id also fails, not just a read.
    code, message = _error_code(
        lambda: cgp.update_profiling_group(
            profilingGroupName=name,
            agentOrchestrationConfig={"profilingEnabled": False},
        )
    )
    assert code == "ResourceNotFoundException", f"update after delete: expected ResourceNotFoundException, got {code}"
    expected_message = (
        f"Unable to find profiling group with accountId: {ctx.account}; profilingGroupName: {name} during update"
    )
    assert message == expected_message, (message, expected_message)

    # The freed name is reusable: the earlier deletion did not merely hide the group.
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
    )
    reused = cgp.describe_profiling_group(profilingGroupName=name)
    assert reused["profilingGroup"]["name"] == name, (
        f"recreated group name mismatch: expected {name}, got {reused['profilingGroup'].get('name')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
