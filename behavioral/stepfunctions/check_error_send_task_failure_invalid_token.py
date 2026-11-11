"""error-send-task-failure-invalid-token."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-send-task-failure-invalid-token"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskFailure with a never-issued task token fails with InvalidToken and the exact message, not
    TaskDoesNotExist; a real token fails its execution with error sim2real.Positive, and the rejected
    call leaves that outcome unchanged."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    activity_arn = sfn.create_activity(name=ctx.unique_name("sim2real-behav-activity-"))["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))

    definition = json.dumps(
        {
            "StartAt": "DoTask",
            "States": {"DoTask": {"Type": "Task", "Resource": activity_arn, "TimeoutSeconds": 300, "End": True}},
        }
    )
    sm_arn = _create_state_machine(ctx, role_arn, definition)

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    real_token = _poll_for_task_token(ctx, activity_arn)
    assert real_token, "never received a task token from GetActivityTask"

    # positive control: a real, live token is accepted and drives the execution to FAILED.
    sfn.send_task_failure(taskToken=real_token, error="sim2real.Positive", cause="positive control")
    desc = _poll_execution_status(ctx, exec_arn, timeout_s=30.0)
    assert desc["status"] == "FAILED", f"expected FAILED from the positive control, got {desc['status']!r}"
    assert desc["error"] == "sim2real.Positive", f"expected the real error to round-trip, got {desc.get('error')!r}"

    # negative: a bogus, never-issued token is rejected outright.
    bogus_token = "not-a-real-task-token-" + ctx.unique_name("")
    code, message = _refusal(
        lambda: sfn.send_task_failure(taskToken=bogus_token, error="sim2real.Behavioral", cause="synthetic failure")
    )
    assert code == "InvalidToken", f"expected InvalidToken, got {code!r}"
    expected_message = "Invalid Token: 'Invalid token'"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # effect absent: the real execution's outcome is untouched by the rejected call.
    desc_after = sfn.describe_execution(executionArn=exec_arn)
    assert desc_after["status"] == "FAILED", desc_after
    assert desc_after["error"] == "sim2real.Positive", desc_after


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


def _create_sfn_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, role_arn, definition):
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's trust policy propagates -- a bounded wait, not a fixed sleep."""
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _poll_for_task_token(ctx, activity_arn, attempts=3):
    sfn = ctx.client("stepfunctions")
    for _ in range(attempts):
        resp = sfn.get_activity_task(activityArn=activity_arn, workerName=ctx.unique_name("worker-"))
        token = resp.get("taskToken")
        if token:
            return token
        time.sleep(1.0)
    return None


def _poll_execution_status(ctx, execution_arn, *, timeout_s=30.0, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    desc = sfn.describe_execution(executionArn=execution_arn)
    while desc["status"] == "RUNNING" and time.monotonic() < deadline:
        time.sleep(interval_s)
        desc = sfn.describe_execution(executionArn=execution_arn)
    return desc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
