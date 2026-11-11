"""history-has-started-and-succeeded."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "history-has-started-and-succeeded"
GROUP = 'execution_history'
SERVICES = ['stepfunctions']

def _role_arn(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=_role_arn(ctx),
        type=sm_type,
        tags=[{"key": "sim2real-behav", "value": "history-has-started-and-succeeded"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _get_history_events(ctx, exec_arn, *, reverse=False):
    sfn = ctx.client("stepfunctions")
    events = []
    kwargs = {"executionArn": exec_arn, "reverseOrder": reverse}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if "nextToken" not in resp:
            break
        kwargs["nextToken"] = resp["nextToken"]
    return events

@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetExecutionHistory includes ExecutionStarted and ExecutionSucceeded events."""
    definition = {
        "StartAt": "P",
        "States": {"P": {"Type": "Pass", "Result": "x", "End": True}},
    }
    sm_arn = _create_state_machine(ctx, definition)
    exec_arn = _start_execution(ctx, sm_arn, input_data={})
    _wait_execution_complete(ctx, exec_arn)
    events = _get_history_events(ctx, exec_arn)
    types = [e["type"] for e in events]
    assert types.count("ExecutionStarted") == 1, (
        f"expected exactly one ExecutionStarted event, got {types.count('ExecutionStarted')} in {types}"
    )
    assert types.count("ExecutionSucceeded") == 1, (
        f"expected exactly one ExecutionSucceeded event, got {types.count('ExecutionSucceeded')} in {types}"
    )
    assert types.index("ExecutionStarted") < types.index("ExecutionSucceeded"), (
        f"ExecutionStarted must precede ExecutionSucceeded in history, got order {types}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
