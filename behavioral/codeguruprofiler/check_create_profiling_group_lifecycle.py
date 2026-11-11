"""create-profiling-group-lifecycle."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-profiling-group-lifecycle"
GROUP = "state"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProfilingGroup persists name/arn/computePlatform/tags; after DeleteProfilingGroup
    the group is permanently gone (DescribeProfilingGroup starts returning ResourceNotFoundException)."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")

    created = cgp.create_profiling_group(
        profilingGroupName=name,
        clientToken=str(uuid.uuid4()),
        computePlatform="Default",
        tags={"env": "sim2real"},
    )["profilingGroup"]
    deleted = False

    def _cleanup():
        if not deleted:
            cgp.delete_profiling_group(profilingGroupName=name)

    ctx.on_cleanup(_cleanup)

    assert created["name"] == name, f"expected created name {name!r}, got {created['name']!r}"
    assert created["computePlatform"] == "Default", (
        f"expected computePlatform 'Default', got {created['computePlatform']!r}"
    )
    assert created["tags"] == {"env": "sim2real"}, f"expected tags {{'env': 'sim2real'}}, got {created['tags']!r}"
    assert created["arn"].endswith(f":profilingGroup/{name}"), (
        f"expected arn to end with ':profilingGroup/{name}', got {created['arn']!r}"
    )

    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert described["name"] == name, f"expected described name {name!r}, got {described['name']!r}"
    assert described["arn"] == created["arn"], (
        f"expected described arn {created['arn']!r} to match created arn, got {described['arn']!r}"
    )
    assert described["computePlatform"] == "Default", (
        f"expected described computePlatform 'Default', got {described['computePlatform']!r}"
    )
    assert described["tags"] == {"env": "sim2real"}, (
        f"expected described tags {{'env': 'sim2real'}}, got {described['tags']!r}"
    )

    cgp.delete_profiling_group(profilingGroupName=name)
    deleted = True

    deadline = time.monotonic() + 30
    last_code = None
    last_message = None
    while time.monotonic() < deadline:
        try:
            cgp.describe_profiling_group(profilingGroupName=name)
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            last_message = err.response["Error"].get("Message")
            if last_code == "ResourceNotFoundException":
                break
        time.sleep(1.5)
    else:
        raise AssertionError(
            f"DescribeProfilingGroup never returned ResourceNotFoundException after delete (last_code={last_code})"
        )
    expected_describe_message = f"CodeGuru Profiler can\u2019t complete the operation because {name} was not found."
    assert last_message == expected_describe_message, (last_message, expected_describe_message)

    try:
        cgp.delete_profiling_group(profilingGroupName=name)
    except ClientError as err:
        redelete_code = err.response["Error"]["Code"]
        redelete_message = err.response["Error"].get("Message")
    else:
        raise AssertionError("a second DeleteProfilingGroup on the dead id SUCCEEDED")
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a second DeleteProfilingGroup on the dead id to raise ResourceNotFoundException, "
        f"got {redelete_code!r}"
    )
    expected_redelete_message = f"ProfilingGroup (name: {name}, accountId: {ctx.account}) not found."
    assert redelete_message == expected_redelete_message, (redelete_message, expected_redelete_message)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
