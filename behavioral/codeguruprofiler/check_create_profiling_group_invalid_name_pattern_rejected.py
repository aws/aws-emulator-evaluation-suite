"""create-profiling-group-invalid-name-pattern-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-profiling-group-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProfilingGroup rejects a profilingGroupName that violates the ^[\\w-]+$ pattern
    (contains a space) with ValidationException, and does not create the resource; a name that
    satisfies the pattern still succeeds (positive control)."""
    cgp = ctx.client("codeguruprofiler")
    invalid_name = ctx.unique_name("sim2real-cgp-") + " invalid"

    code, message = _error_code(
        lambda: cgp.create_profiling_group(
            profilingGroupName=invalid_name, clientToken=str(uuid.uuid4())
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException rejecting name {invalid_name!r} (contains a space), got {code!r}"
    )
    expected_message = (
        f"1 validation error detected: Value '{invalid_name}' at 'profilingGroupName' failed "
        r"to satisfy constraint: Member must satisfy regular expression pattern: [\w-]+"
    )
    assert message == expected_message, (message, expected_message)

    listed = cgp.list_profiling_groups(maxResults=1000)["profilingGroupNames"]
    assert invalid_name not in listed, (
        f"rejected name {invalid_name!r} must not appear in ListProfilingGroups, got {listed!r}"
    )

    valid_name = ctx.unique_name("sim2real-cgp-")
    cgp.create_profiling_group(profilingGroupName=valid_name, clientToken=str(uuid.uuid4()))
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=valid_name))
    described_name = cgp.describe_profiling_group(profilingGroupName=valid_name)["profilingGroup"][
        "name"
    ]
    assert described_name == valid_name, (
        f"expected DescribeProfilingGroup to report name {valid_name!r}, got {described_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
