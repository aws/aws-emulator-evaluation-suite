"""delete-profiling-group-removes-visibility."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-profiling-group-removes-visibility"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected ResourceNotFoundException but call succeeded: {result!r}")


def _list_names(cgp):
    names = []
    kwargs = {}
    while True:
        resp = cgp.list_profiling_groups(**kwargs)
        names.extend(resp.get("profilingGroupNames", []))
        nxt = resp.get("nextToken")
        if not nxt:
            break
        kwargs["nextToken"] = nxt
    return names


def _wait_for_absence(cgp, name, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    names = _list_names(cgp)
    while name in names and time.monotonic() < deadline:
        time.sleep(interval_s)
        names = _list_names(cgp)
    if name in names:
        raise AssertionError(
            f"{name!r} still present in ListProfilingGroups {timeout_s}s after delete"
        )
    return names


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteProfilingGroup, DescribeProfilingGroup, GetPolicy and UpdateProfilingGroup fail with
    ResourceNotFoundException and their exact messages, ListProfilingGroups omits the group, and the name can
    be created again.
    """
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-del-")
    cgp.create_profiling_group(profilingGroupName=name, clientToken=str(uuid.uuid4()))

    cgp.delete_profiling_group(profilingGroupName=name)

    describe_code, describe_message = _error_code(lambda: cgp.describe_profiling_group(profilingGroupName=name))
    assert describe_code == "ResourceNotFoundException", (
        f"describe_profiling_group after delete: expected ResourceNotFoundException, "
        f"got {describe_code!r}"
    )
    expected_describe_message = f"CodeGuru Profiler can\u2019t complete the operation because {name} was not found."
    assert describe_message == expected_describe_message, (describe_message, expected_describe_message)

    policy_code, policy_message = _error_code(lambda: cgp.get_policy(profilingGroupName=name))
    assert policy_code == "ResourceNotFoundException", (
        f"get_policy after delete: expected ResourceNotFoundException, got {policy_code!r}"
    )
    expected_policy_message = f"No profiling group with accountId: {ctx.account}; name: {name} was found."
    assert policy_message == expected_policy_message, (policy_message, expected_policy_message)

    update_code, update_message = _error_code(
        lambda: cgp.update_profiling_group(
            profilingGroupName=name, agentOrchestrationConfig={"profilingEnabled": True}
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"update_profiling_group on deleted group: expected ResourceNotFoundException, "
        f"got {update_code!r}"
    )
    expected_update_message = (
        f"Unable to find profiling group with accountId: {ctx.account}; profilingGroupName: {name} during update"
    )
    assert update_message == expected_update_message, (update_message, expected_update_message)

    names = _wait_for_absence(cgp, name)
    assert name not in names, f"{name!r} unexpectedly present in ListProfilingGroups: {names!r}"

    cgp.create_profiling_group(profilingGroupName=name, clientToken=str(uuid.uuid4()))
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    recreated = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert recreated["name"] == name, (
        f"freed name {name!r} not reusable: describe returned name {recreated.get('name')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
