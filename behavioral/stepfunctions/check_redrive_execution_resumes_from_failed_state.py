"""redrive-execution-resumes-from-failed-state."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "redrive-execution-resumes-from-failed-state"
GROUP = "server-side"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RedriveExecution server-side resumes a FAILED STANDARD execution from its failed
    Task state rather than restarting the whole workflow: states that already succeeded
    are not re-entered, and the redrive is recorded as an ExecutionRedriven history event."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_basic_execution_role(ctx)
    activity_arn = _create_activity(ctx)

    definition = json.dumps(
        {
            "StartAt": "First",
            "States": {
                "First": {
                    "Type": "Pass",
                    "Result": {"marker": "first-run"},
                    "ResultPath": "$.first",
                    "Next": "SecondFails",
                },
                "SecondFails": {
                    "Type": "Task",
                    "Resource": activity_arn,
                    "Next": "Third",
                },
                "Third": {"Type": "Pass", "End": True},
            },
        }
    )
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps({"orig": True})
    )["executionArn"]

    # Drain and fail the first activity task -> the execution fails at SecondFails.
    token1 = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_failure(taskToken=token1, error="ProbeError", cause="induced failure")

    final1 = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60,
    )
    assert final1["status"] == "FAILED", f"expected FAILED, got {final1['status']}"
    assert final1["redriveStatus"] == "REDRIVABLE", (
        f"expected REDRIVABLE, got {final1['redriveStatus']}"
    )

    first_entered_before = _count_state_entered(ctx, exec_arn, "First")
    assert first_entered_before == 1, f"expected First entered once, got {first_entered_before}"

    # Redrive: must resume at SecondFails, not re-run First.
    sfn.redrive_execution(executionArn=exec_arn)

    resumed = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] == "RUNNING",
        timeout_s=30,
    )
    assert resumed["status"] == "RUNNING", f"expected RUNNING after redrive, got {resumed['status']}"

    token2 = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_success(taskToken=token2, output=json.dumps({"done": True}))

    final2 = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60,
    )
    assert final2["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {final2}"
    assert final2["redriveCount"] == 1, f"expected redriveCount 1, got {final2.get('redriveCount')}"

    first_entered_after = _count_state_entered(ctx, exec_arn, "First")
    assert first_entered_after == 1, (
        f"redrive must not re-enter already-succeeded 'First' state, saw {first_entered_after} entries"
    )

    events = sfn.get_execution_history(executionArn=exec_arn)["events"]
    redriven_events = [e for e in events if e["type"] == "ExecutionRedriven"]
    assert len(redriven_events) == 1, f"expected exactly one ExecutionRedriven event, got {redriven_events}"


def _create_basic_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-activity-")
    arn = sfn.create_activity(
        name=name, tags=[{"key": "sim2real", "value": CHECK}]
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, definition: str, role_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    last_error = None
    for _ in range(15):
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except Exception as exc:  # noqa: BLE001 - retry on IAM role propagation delay
            last_error = exc
            time.sleep(2)
    raise AssertionError(f"could not create state machine (role propagation?): {last_error}")


def _poll_activity_task(ctx, activity_arn: str, timeout_s: float = 60.0) -> str:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.get_activity_task(activityArn=activity_arn, workerName="sim2real-behav")
        token = resp.get("taskToken")
        if token:
            return token
    raise AssertionError("never received an activity task in time")


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 1.0) -> Any:
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last result: {result}")


def _count_state_entered(ctx, exec_arn: str, state_name: str) -> int:
    sfn = ctx.client("stepfunctions")
    count = 0
    token = None
    while True:
        kwargs = {"executionArn": exec_arn}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        for event in page["events"]:
            details = event.get("stateEnteredEventDetails")
            if details and details.get("name") == state_name:
                count += 1
        token = page.get("nextToken")
        if not token:
            break
    return count


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
