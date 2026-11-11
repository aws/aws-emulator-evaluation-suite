"""redrive-execution-client-token-idempotent-redrive-date."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-execution-client-token-idempotent-redrive-date"
GROUP = "execution_lifecycle"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RedriveExecution with a repeated clientToken returns the same redriveDate it returned
    the first time, whether the execution is now RUNNING, SUCCEEDED or re-ABORTED."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_execution_role(ctx)
    activity_arn = _create_activity(ctx)
    sm_arn = _create_state_machine(ctx, _definition(activity_arn), role_arn)

    # ---- RUNNING, then SUCCEEDED: redrive once, then repeat the same token at each state ----
    exec_a = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({}))["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_a))
    token_a = ctx.unique_name("sim2real-behav-token-")
    _fail_pending_task(ctx, activity_arn)
    _wait_for_status(ctx, exec_a, {"FAILED"}, timeout_s=60)

    first_a = sfn.redrive_execution(executionArn=exec_a, clientToken=token_a)
    _wait_for_status(ctx, exec_a, {"RUNNING"}, timeout_s=30)

    repeat_running = sfn.redrive_execution(executionArn=exec_a, clientToken=token_a)
    assert repeat_running["redriveDate"] == first_a["redriveDate"], (
        f"repeating clientToken {token_a!r} while RUNNING returned redriveDate "
        f"{repeat_running['redriveDate']!r}, expected the original {first_a['redriveDate']!r}"
    )

    _succeed_pending_task(ctx, activity_arn)
    _wait_for_status(ctx, exec_a, {"SUCCEEDED"}, timeout_s=60)

    repeat_succeeded = sfn.redrive_execution(executionArn=exec_a, clientToken=token_a)
    assert repeat_succeeded["redriveDate"] == first_a["redriveDate"], (
        f"repeating clientToken {token_a!r} after SUCCEEDED returned redriveDate "
        f"{repeat_succeeded['redriveDate']!r}, expected the original {first_a['redriveDate']!r}"
    )
    after_a = sfn.describe_execution(executionArn=exec_a)
    assert after_a["redriveCount"] == 1, (
        f"a cached idempotent response must not itself redrive again, "
        f"got redriveCount={after_a.get('redriveCount')!r}"
    )

    # ---- re-ABORTED: redrive once, abort the resumed run, then repeat the same token ----
    exec_b = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({}))["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_b))
    token_b = ctx.unique_name("sim2real-behav-token-")
    _fail_pending_task(ctx, activity_arn)
    _wait_for_status(ctx, exec_b, {"FAILED"}, timeout_s=60)

    first_b = sfn.redrive_execution(executionArn=exec_b, clientToken=token_b)
    _wait_for_status(ctx, exec_b, {"RUNNING"}, timeout_s=30)
    sfn.stop_execution(executionArn=exec_b, error="sim2real-abort", cause="deliberate re-abort")
    _wait_for_status(ctx, exec_b, {"ABORTED"}, timeout_s=30)

    repeat_aborted = sfn.redrive_execution(executionArn=exec_b, clientToken=token_b)
    assert repeat_aborted["redriveDate"] == first_b["redriveDate"], (
        f"repeating clientToken {token_b!r} after re-ABORTED returned redriveDate "
        f"{repeat_aborted['redriveDate']!r}, expected the original {first_b['redriveDate']!r}"
    )
    after_b = sfn.describe_execution(executionArn=exec_b)
    assert after_b["status"] == "ABORTED", (
        f"a cached idempotent response must not revive an ABORTED execution, got {after_b!r}"
    )
    assert after_b["redriveCount"] == 1, (
        f"a cached idempotent response must not itself redrive again, "
        f"got redriveCount={after_b.get('redriveCount')!r}"
    )

    # ---- positive control: a FRESH clientToken on the same ABORTED execution is accepted ----
    fresh = sfn.redrive_execution(executionArn=exec_b)
    assert fresh["redriveDate"] != first_b["redriveDate"], (
        "a fresh (auto-generated) clientToken must redrive for real, not replay the cached response"
    )
    after_fresh = sfn.describe_execution(executionArn=exec_b)
    assert after_fresh["redriveCount"] == 2, (
        f"a fresh clientToken redrives the execution a second time, "
        f"got redriveCount={after_fresh.get('redriveCount')!r}"
    )


def _definition(activity_arn: str) -> str:
    return json.dumps({
        "StartAt": "DoWork",
        "States": {"DoWork": {"Type": "Task", "Resource": activity_arn, "End": True}},
    })


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-activity-")
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": CHECK}])["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, definition: str, role_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _poll_activity_task(ctx, activity_arn: str, *, timeout_s: float = 60.0) -> str:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        token = sfn.get_activity_task(
            activityArn=activity_arn, workerName="sim2real-behav").get("taskToken")
        if token:
            return token
    raise AssertionError(f"no activity task arrived on {activity_arn} within {timeout_s}s")


def _fail_pending_task(ctx, activity_arn: str) -> None:
    sfn = ctx.client("stepfunctions")
    token = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_failure(taskToken=token, error="sim2real-induced", cause="deliberate failure")


def _succeed_pending_task(ctx, activity_arn: str) -> None:
    sfn = ctx.client("stepfunctions")
    token = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_success(taskToken=token, output=json.dumps({"ok": True}))


def _wait_for_status(ctx, exec_arn: str, statuses, *, timeout_s: float, interval_s: float = 2.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} status not in {statuses} within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn: str) -> None:
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
