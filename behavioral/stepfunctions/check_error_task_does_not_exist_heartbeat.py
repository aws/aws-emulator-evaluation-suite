"""error-task-does-not-exist-heartbeat."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "error-task-does-not-exist-heartbeat"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskHeartbeat on a token whose task already completed through SendTaskSuccess fails with
    TaskTimedOut and the exact message (not TaskDoesNotExist or InvalidToken), after the execution
    SUCCEEDED."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    activity_name = ctx.unique_name("sim2real-behav-activity-hb-")
    activity_arn = sfn.create_activity(
        name=activity_name, tags=[{"key": "sim2real", "value": CHECK}]
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))

    sm_name = ctx.unique_name("sim2real-behav-sm-hb-")
    definition = json.dumps(
        {
            "StartAt": "DoTask",
            "States": {"DoTask": {"Type": "Task", "Resource": activity_arn, "TimeoutSeconds": 300, "End": True}},
        }
    )
    sm_arn = _create_state_machine_with_role_wait(sfn, sm_name, definition, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]

    task_token = _poll_for_task_token(ctx, activity_arn)
    assert task_token, "never received a task token from GetActivityTask"

    # positive control: a heartbeat on a still-live (not yet completed) task succeeds, so the
    # eventual rejection below cannot be "heartbeats are always rejected".
    sfn.send_task_heartbeat(taskToken=task_token)

    # Complete the task -- the token is now spent. The execution recording the completion is
    # itself eventually consistent, so wait for it to settle before probing the retired token:
    # heartbeating too soon after SendTaskSuccess can race ahead of that and return no error.
    sfn.send_task_success(taskToken=task_token, output="{}")
    desc = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
    )
    assert desc["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {desc['status']!r}"

    code, message = _error_code(lambda: sfn.send_task_heartbeat(taskToken=task_token))
    assert code == "TaskTimedOut", f"expected TaskTimedOut, got {code!r}"
    expected_message = f"Task Timed Out: '{activity_arn}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_for_task_token(ctx, activity_arn, attempts=3):
    sfn = ctx.client("stepfunctions")
    for _ in range(attempts):
        resp = sfn.get_activity_task(activityArn=activity_arn, workerName=ctx.unique_name("worker-"))
        token = resp.get("taskToken")
        if token:
            return token
        time.sleep(1.0)
    return None


def _create_sfn_role(ctx, inline_statements=None):
    import json as _json
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-sfn-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=_json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_state_machine_with_role_wait(sfn, name: str, definition: str, role_arn: str, timeout: float = 90.0) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created role's
    trust/PassRole grant propagates -- a bounded retry, not a fixed sleep, since propagation
    latency varies."""
    from botocore.exceptions import ClientError

    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            return sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"create_state_machine did not succeed within {timeout}s of role creation: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
