"""activity-task-failure-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-task-failure-lifecycle"
GROUP = 'state-machine'
SERVICES = ['stepfunctions']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskFailure drives the execution to FAILED and preserves error/cause."""
    sfn = ctx.client("stepfunctions")
    activity_arn = _create_activity(ctx, ctx.unique_name("sim2real-behav-sfn-activity-fail-"))

    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(
        ctx,
        role_arn,
        _activity_task_definition(activity_arn),
        name=ctx.unique_name("sim2real-behav-sfn-activity-fail-sm-"),
    )
    started = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-run-"), input="{}"
    )
    execution_arn = started["executionArn"]
    ctx.on_cleanup(lambda: _stop_execution(sfn, execution_arn))

    task = _poll_until(
        lambda: sfn.get_activity_task(activityArn=activity_arn),
        lambda t: t.get("taskToken"),
        timeout_s=20,
        interval_s=1,
    )
    task_token = task["taskToken"]

    sfn.send_task_failure(taskToken=task_token, error="MyError", cause="behavioral failure")

    final = _poll_until(
        lambda: sfn.describe_execution(executionArn=execution_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=20,
        interval_s=1,
    )
    assert final["status"] == "FAILED", f"expected FAILED, got {final['status']}"
    assert final.get("error") == "MyError", f"expected error MyError, got {final.get('error')!r}"
    assert final.get("cause") == "behavioral failure", (
        f"expected cause 'behavioral failure', got {final.get('cause')!r}"
    )


# ===== helpers =====

# A minimal Amazon States Language definition: a single Pass state.
_PASS_DEFINITION = json.dumps(
    {
        "Comment": "Simple pass-through state machine for behavioral checks",
        "StartAt": "PassState",
        "States": {"PassState": {"Type": "Pass", "Result": {"ok": True}, "End": True}},
    }
)

_SFN_TRUST_POLICY = json.dumps(
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

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "states:StartExecution",
                    "states:DescribeExecution",
                    "states:StopExecution",
                    "states:RedriveExecution",
                    "states:DescribeStateMachine",
                ],
                "Resource": "*",
            }
        ],
    }
)


_GONE_CODES = ("NoSuchEntity", "ExecutionDoesNotExist", "ActivityDoesNotExist",
               "StateMachineDoesNotExist")


def _unless_gone(fn):
    """Run a teardown call; return only when the resource is already gone, raise the rest."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE_CODES:
            raise


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _create_sfn_role(ctx) -> str:
    """An execution role real Step Functions accepts on CreateStateMachine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY
    )

    def _cleanup():
        _unless_gone(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"))
        _unless_gone(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_state_machine(ctx, role_arn: str, definition: str, *, name: str | None = None) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sfn-")
    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise AssertionError(
            f"could not create state machine after role propagation wait: {last_err}"
        )
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


def _activity_task_definition(activity_arn: str) -> str:
    """A single Task state that waits on a task token, driven by an Activity
    resource so the check can exercise GetActivityTask / SendTask*."""
    return json.dumps(
        {
            "Comment": "Single activity task state machine",
            "StartAt": "DoTask",
            "States": {"DoTask": {"Type": "Task", "Resource": activity_arn, "End": True}},
        }
    )


def _create_activity(ctx, name: str) -> str:
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=name, tags=[{"key": "sim2real-check", "value": CHECK}]
    )["activityArn"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: sfn.delete_activity(activityArn=arn)))
    return arn


def _stop_execution(sfn, execution_arn: str) -> None:
    """StopExecution is a no-op on a terminal execution, so registering it unconditionally
    keeps a mid-check failure from leaving a RUNNING execution behind."""
    _unless_gone(
        lambda: sfn.stop_execution(
            executionArn=execution_arn, error="Cleanup", cause="test cleanup"
        )
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
