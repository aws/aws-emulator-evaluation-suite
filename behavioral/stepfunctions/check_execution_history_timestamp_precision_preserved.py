"""execution-history-timestamp-precision-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "execution-history-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["stepfunctions"]

_SCENARIO = "execution-history-timestamp-precision-preserved"
_PREFIX = "sim2real-sfn-ts-"
_TAGS_UPPER = [
    {"Key": "sim2real", "Value": _SCENARIO},
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": _PREFIX},
]
_TAGS_LOWER = [
    {"key": "sim2real", "value": _SCENARIO},
    {"key": "sim2real:managed", "value": "true"},
    {"key": "sim2real:prefix", "value": _PREFIX},
]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeExecution's startDate and stopDate equal the ExecutionStarted and ExecutionSucceeded event
    timestamps exactly, history timestamps never decrease, and at least one carries sub-second
    resolution."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_role_for_state_machine(ctx)

    definition = json.dumps(
        {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}
    )
    sm_name = ctx.unique_name(_PREFIX)
    sm_arn = sfn.create_state_machine(
        name=sm_name, definition=definition, roleArn=role_arn, tags=_TAGS_LOWER
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    exec_name = ctx.unique_name(f"{_PREFIX}exec-")
    execution_arn = sfn.start_execution(stateMachineArn=sm_arn, name=exec_name, input="{}")[
        "executionArn"
    ]

    desc = _wait_execution_terminal(ctx, sfn, execution_arn, timeout_s=60)
    assert desc["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {desc['status']}"
    assert "startDate" in desc and "stopDate" in desc, f"missing startDate/stopDate in {desc}"

    events = sfn.get_execution_history(executionArn=execution_arn)["events"]
    assert len(events) >= 2, f"expected at least 2 history events, got {len(events)}"

    timestamps = [e["timestamp"] for e in events]
    for earlier, later in zip(timestamps, timestamps[1:]):
        assert earlier <= later, f"history events out of order: {earlier} > {later}"

    started = next(e for e in events if e["type"] == "ExecutionStarted")
    succeeded = next(e for e in events if e["type"] == "ExecutionSucceeded")

    assert started["timestamp"] == desc["startDate"], (
        f"ExecutionStarted event timestamp {started['timestamp']} != "
        f"DescribeExecution startDate {desc['startDate']}"
    )
    assert succeeded["timestamp"] == desc["stopDate"], (
        f"ExecutionSucceeded event timestamp {succeeded['timestamp']} != "
        f"DescribeExecution stopDate {desc['stopDate']}"
    )
    assert desc["startDate"] <= desc["stopDate"], (
        f"startDate {desc['startDate']} after stopDate {desc['stopDate']}"
    )

    # A target that round-trips timestamps through a whole-second format would still
    # satisfy every equality/ordering assertion above (both reads would agree on the
    # same rounded value). Demand that at least one recorded timestamp actually carries
    # sub-second resolution, so precision loss is observable rather than merely
    # self-consistent.
    assert any(ts.microsecond != 0 for ts in timestamps), (
        f"every history event timestamp landed exactly on a whole second: {timestamps} "
        "-- sub-second precision does not appear to be preserved"
    )


def _create_role_for_state_machine(ctx) -> str:
    iam = ctx.client("iam")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_name = ctx.unique_name("sim2real-sfn-tsrole-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy, Tags=_TAGS_UPPER
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _wait_execution_terminal(ctx, sfn, execution_arn, timeout_s=60.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=execution_arn)
        if desc["status"] != "RUNNING":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"execution did not terminate in {timeout_s}s, last status: {desc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
