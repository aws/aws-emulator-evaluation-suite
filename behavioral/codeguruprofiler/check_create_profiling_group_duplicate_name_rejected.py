"""create-profiling-group-duplicate-name-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-profiling-group-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the duplicate CreateProfilingGroup call to be rejected, but it "
        f"SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProfilingGroup with a name that already exists in the account is rejected with
    ConflictException and does not disturb the existing group; creating under a fresh, distinct
    name still succeeds (positive control)."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-")

    original = cgp.create_profiling_group(
        profilingGroupName=name, clientToken=str(uuid.uuid4()), tags={"marker": "original"}
    )["profilingGroup"]
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    code, message = _error_code(
        lambda: cgp.create_profiling_group(
            profilingGroupName=name, clientToken=str(uuid.uuid4()), tags={"marker": "duplicate"}
        )
    )
    assert code == "ConflictException", (
        f"expected ConflictException for a duplicate profiling group name, got {code!r}"
    )
    expected_message = f"ProfilingGroup (name: {name}, accountId: {ctx.account}) already exists."
    assert message == expected_message, (message, expected_message)

    # effect absent: the original group's tags were not overwritten by the rejected duplicate
    described = cgp.describe_profiling_group(profilingGroupName=name)["profilingGroup"]
    assert described["tags"] == {"marker": "original"}, (
        f"expected the original group's tags to survive the rejected duplicate create, "
        f"got tags={described['tags']!r}"
    )
    assert described["arn"] == original["arn"], (
        f"expected the original group's arn to be unchanged by the rejected duplicate, "
        f"got arn={described['arn']!r}, original was {original['arn']!r}"
    )

    # positive control: a distinct name still succeeds
    other_name = ctx.unique_name("sim2real-cgp-other-")
    cgp.create_profiling_group(profilingGroupName=other_name, clientToken=str(uuid.uuid4()))
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=other_name))
    other_described_name = cgp.describe_profiling_group(profilingGroupName=other_name)["profilingGroup"][
        "name"
    ]
    assert other_described_name == other_name, (
        f"expected a create under a fresh name to still succeed, got name={other_described_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
