"""get-activity-task-blocks-until-execution-schedules-task."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-activity-task-blocks-until-execution-schedules-task"
GROUP = "data-plane"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A long-poll GetActivityTask issued before any execution exists stays pending, then returns
    the task StartExecution schedules while it waits, carrying the execution's input."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    sm_arn = _create_state_machine_with_activity(ctx, role_arn, activity_arn)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(sfn.get_activity_task, activityArn=activity_arn, workerName="poller")
        # Repeatedly confirm the long-poll has NOT resolved yet -- no execution has scheduled
        # anything to this activity. A bounded retry (not a single sleep) so a target that
        # resolves the call quickly, at any point inside the 3s window, is caught.
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            assert not future.done(), "GetActivityTask returned before any work was scheduled"
            time.sleep(0.5)

        exec_input = {"marker": "blocked-poll-test"}
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, input=json.dumps(exec_input)
        )["executionArn"]

        task = future.result(timeout=_budget_s(ctx, 65))

    assert task["taskToken"], "pending GetActivityTask never received a task token"
    actual_input = json.loads(task["input"])
    assert actual_input == exec_input, f"expected task input {exec_input!r}, got {actual_input!r}"

    sfn.send_task_success(taskToken=task["taskToken"], output=json.dumps({"ok": True}))
    final = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=_budget_s(ctx, 30.0),
    )
    assert final["status"] == "SUCCEEDED", f"expected SUCCEEDED after send_task_success, got {final['status']!r}"


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))

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
