"""e2e-activity-worker-heartbeat-success-pipeline."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-activity-worker-heartbeat-success-pipeline"
GROUP = "e2e"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full activity-worker pipeline: schedule, heartbeat repeatedly, then succeed -- the
    execution transitions to SUCCEEDED carrying the worker's own output as a consequence."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    heartbeat_seconds = 6
    sm_arn = _create_state_machine_with_activity(
        ctx, role_arn, activity_arn, heartbeat_seconds=heartbeat_seconds
    )

    exec_input = {"job": "widget-42"}
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(exec_input))[
        "executionArn"
    ]

    task = _poll_until(
        lambda: sfn.get_activity_task(activityArn=activity_arn, workerName="worker-1"),
        lambda t: bool(t.get("taskToken")),
        timeout_s=30.0,
        interval_s=1.0,
    )
    token = task["taskToken"]
    assert json.loads(task["input"]) == exec_input

    # Three heartbeats spaced 3s apart span ~9s total -- longer than the single
    # HeartbeatSeconds=6 window -- while each individual gap stays well inside it. A
    # target that ignored the heartbeats (or didn't reset the clock on each one) would
    # already have timed out the task by the time send_task_success is called below.
    for _ in range(3):
        time.sleep(3)
        sfn.send_task_heartbeat(taskToken=token)

    desc = sfn.describe_execution(executionArn=exec_arn)
    assert desc["status"] == "RUNNING", (
        f"execution should still be RUNNING via heartbeats past the {heartbeat_seconds}s "
        f"window, got {desc['status']!r}"
    )

    worker_output = {"result": "processed", "job": "widget-42"}
    sfn.send_task_success(taskToken=token, output=json.dumps(worker_output))

    desc = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
    )
    assert desc["status"] == "SUCCEEDED"
    assert json.loads(desc["output"]) == worker_output


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


def _create_state_machine_with_activity(
    ctx, role_arn: str, activity_arn: str, heartbeat_seconds: int = 5
) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sfn-sm-")
    definition = json.dumps(
        {
            "StartAt": "DoTask",
            "States": {
                "DoTask": {
                    "Type": "Task",
                    "Resource": activity_arn,
                    "TimeoutSeconds": 120,
                    "HeartbeatSeconds": heartbeat_seconds,
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
