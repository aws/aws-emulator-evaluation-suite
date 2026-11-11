"""send-task-success-with-invalid-token-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-success-with-invalid-token-fails"
GROUP = 'error-semantics'
SERVICES = ['stepfunctions']
_INVALID_TOKEN_MESSAGE = "Invalid Token: 'Invalid token'"


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskSuccess with a syntactically bogus, never-issued taskToken raises InvalidToken
    (never succeeds silently), while a real task token issued by a live execution still
    completes normally -- proving the rejection is about the token, not a broken account."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    sm_arn = _create_state_machine_with_activity(ctx, role_arn, activity_arn)

    # positive control: a real task token from a live execution succeeds normally.
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    task = sfn.get_activity_task(activityArn=activity_arn, workerName=ctx.unique_name("worker-"))
    token = task["taskToken"]
    assert token

    sfn.send_task_success(taskToken=token, output=json.dumps({"ok": True}))
    desc = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
    )
    assert desc["status"] == "SUCCEEDED", f"unexpected status: {desc['status']!r}"
    assert json.loads(desc["output"]) == {"ok": True}

    # negative: a syntactically bogus token that was never issued raises InvalidToken.
    error = _rejected_error(lambda: sfn.send_task_success(taskToken="not-a-real-token", output="{}"))
    assert error.get("Code") == "InvalidToken", f"expected InvalidToken, got {error!r}"
    assert error.get("Message") == _INVALID_TOKEN_MESSAGE, (
        f"expected InvalidToken message {_INVALID_TOKEN_MESSAGE!r}, got {error.get('Message')!r}"
    )


def _rejected_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected SendTaskSuccess to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
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
