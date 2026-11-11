"""send-task-success-after-completion-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-success-after-completion-rejected"
GROUP = "data-plane"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second SendTaskSuccess on an already-completed task token fails TaskTimedOut with the exact
    message, the execution keeps the first output {"first": true}, and a fresh task still succeeds."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    sm_arn = _create_state_machine_with_activity(ctx, role_arn, activity_arn)

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    task = sfn.get_activity_task(activityArn=activity_arn, workerName="w1")
    token = task["taskToken"]
    assert token, f"expected a non-empty taskToken from GetActivityTask, got {token!r}"

    sfn.send_task_success(taskToken=token, output=json.dumps({"first": True}))
    _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
    )

    code, message = _error(
        lambda: sfn.send_task_success(taskToken=token, output=json.dumps({"second": True}))
    )
    assert code == "TaskTimedOut", f"unexpected code: {code!r}"
    expected = f"Task Timed Out: '{activity_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the execution's output is still the first (winning) success, unaffected.
    desc = sfn.describe_execution(executionArn=exec_arn)
    assert desc["status"] == "SUCCEEDED", f"expected SUCCEEDED (winning result unaffected), got {desc['status']!r}"
    assert json.loads(desc["output"]) == {"first": True}, f"expected original output {{'first': True}}, got {desc['output']!r}"

    # positive control: a *fresh* task token on a new execution still succeeds normally.
    exec_arn2 = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    task2 = sfn.get_activity_task(activityArn=activity_arn, workerName="w1")
    sfn.send_task_success(taskToken=task2["taskToken"], output=json.dumps({"control": True}))
    desc2 = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn2),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
    )
    assert desc2["status"] == "SUCCEEDED", f"expected fresh execution to SUCCEED, got {desc2['status']!r}"
    assert json.loads(desc2["output"]) == {"control": True}, f"expected control output {{'control': True}}, got {desc2['output']!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _create_activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sfn-activity-")
    arn = sfn.create_activity(name=name)["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine_with_activity(ctx, role_arn: str, activity_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sfn-sm-")
    definition = json.dumps(
        {
            "StartAt": "DoTask",
            "States": {
                "DoTask": {
                    "Type": "Task",
                    "Resource": activity_arn,
                    "TimeoutSeconds": 90,
                    "End": True,
                }
            },
        }
    )
    last_err = None
    for _ in range(15):
        try:
            resp = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)
            arn = resp["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
