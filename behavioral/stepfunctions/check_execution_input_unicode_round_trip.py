"""execution-input-unicode-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "execution-input-unicode-round-trip"
GROUP = "representation"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Non-ASCII/multi-byte unicode characters in execution input survive unchanged
    through StartExecution, DescribeExecution (input/output), and the ExecutionStarted/
    ExecutionSucceeded event payloads in GetExecutionHistory."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_role_for_state_machine(ctx)

    definition = json.dumps(
        {"StartAt": "PassThrough", "States": {"PassThrough": {"Type": "Pass", "End": True}}}
    )
    sm_name = ctx.unique_name("sim2real-sfn-unicode-")
    sm_arn = sfn.create_state_machine(
        name=sm_name,
        definition=definition,
        roleArn=role_arn,
        tags=[{"key": "sim2real", "value": "execution-input-unicode-round-trip"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    payload = {
        "greeting": "héllo wörld 日本語 emoji \U0001f680 espa\u00f1ol \u0645\u0631\u062d\u0628\u0627",
    }
    input_json = json.dumps(payload, ensure_ascii=False)

    exec_name = ctx.unique_name("sim2real-sfn-unicode-exec-")
    execution_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=exec_name, input=input_json
    )["executionArn"]

    desc = _wait_execution_terminal(ctx, sfn, execution_arn, timeout_s=60)
    assert desc["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {desc['status']}"
    desc_input = json.loads(desc["input"])
    assert desc_input == payload, f"DescribeExecution input mismatch: expected {payload!r}, got {desc_input!r}"
    desc_output = json.loads(desc["output"])
    assert desc_output == payload, f"DescribeExecution output mismatch: expected {payload!r}, got {desc_output!r}"

    events = sfn.get_execution_history(executionArn=execution_arn, includeExecutionData=True)[
        "events"
    ]
    started = next(e for e in events if e["type"] == "ExecutionStarted")
    succeeded = next(e for e in events if e["type"] == "ExecutionSucceeded")
    started_input = json.loads(started["executionStartedEventDetails"]["input"])
    assert started_input == payload, (
        f"ExecutionStarted event input mismatch: expected {payload!r}, got {started_input!r}"
    )
    succeeded_output = json.loads(succeeded["executionSucceededEventDetails"]["output"])
    assert succeeded_output == payload, (
        f"ExecutionSucceeded event output mismatch: expected {payload!r}, got {succeeded_output!r}"
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
    role_name = ctx.unique_name("sim2real-sfn-unirole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "execution-input-unicode-round-trip"}],
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
