"""send-task-heartbeat-invalid-token-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-task-heartbeat-invalid-token-fails"
GROUP = 'error-semantics'
SERVICES = ['stepfunctions']


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskHeartbeat against a bogus taskToken must raise InvalidToken -- distinct from a
    real, live token, which a positive control proves the very same call accepts -- and the
    bogus call must leave the real task and its execution untouched."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    activity_name = ctx.unique_name("sim2real-behav-activity-hbtok-")
    activity_arn = sfn.create_activity(name=activity_name)["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))

    sm_name = ctx.unique_name("sim2real-behav-sm-hbtok-")
    definition = json.dumps(
        {
            "StartAt": "DoTask",
            "States": {
                "DoTask": {
                    "Type": "Task",
                    "Resource": activity_arn,
                    "HeartbeatSeconds": 60,
                    "TimeoutSeconds": 300,
                    "End": True,
                }
            },
        }
    )
    sm_arn = _create_state_machine(ctx, role_arn, sm_name, definition)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]

    task_token = _poll_for_task_token(ctx, activity_arn)
    assert task_token, "never received a task token from GetActivityTask"

    # Positive control: the real, live token must be accepted before we probe the bogus one --
    # otherwise a target that rejects every heartbeat would score identically to a correct one.
    sfn.send_task_heartbeat(taskToken=task_token)

    code, message = _error(lambda: sfn.send_task_heartbeat(taskToken="not-a-real-token"))
    assert code == "InvalidToken", f"expected InvalidToken, got {code!r}"
    expected = "Invalid Token: 'Invalid token'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The bogus call must not have disturbed the real task: the execution is still running and
    # the live token is still accepted.
    desc = sfn.describe_execution(executionArn=exec_arn)
    assert desc["status"] == "RUNNING", f"execution should be unaffected by the bogus heartbeat, got {desc['status']!r}"
    sfn.send_task_heartbeat(taskToken=task_token)

    sfn.send_task_success(taskToken=task_token, output="{}")


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to raise, but it succeeded")


def _poll_for_task_token(ctx, activity_arn, attempts=3):
    sfn = ctx.client("stepfunctions")
    for _ in range(attempts):
        resp = sfn.get_activity_task(activityArn=activity_arn, workerName=ctx.unique_name("worker-"))
        token = resp.get("taskToken")
        if token:
            return token
        time.sleep(1.0)
    return None


def _create_sfn_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-hbtok-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, role_arn, name, definition):
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's trust policy propagates."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)["stateMachineArn"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
