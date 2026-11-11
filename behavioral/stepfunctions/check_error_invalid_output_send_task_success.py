"""error-invalid-output-send-task-success."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-invalid-output-send-task-success"
GROUP = "error-semantics"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendTaskSuccess with non-JSON output fails with InvalidOutput and the exact message without
    completing the task: the execution stays RUNNING, a heartbeat on the token still succeeds, and a
    later SendTaskSuccess with valid output brings the execution to SUCCEEDED."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    activity_name = ctx.unique_name("sim2real-behav-activity-out-")
    activity_arn = sfn.create_activity(
        name=activity_name, tags=[{"key": "sim2real-check", "value": CHECK}]
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))

    sm_name = ctx.unique_name("sim2real-behav-sm-out-")
    definition = json.dumps(
        {
            "StartAt": "DoTask",
            "States": {
                "DoTask": {
                    "Type": "Task",
                    "Resource": activity_arn,
                    "TimeoutSeconds": 300,
                    "HeartbeatSeconds": 60,
                    "End": True,
                }
            },
        }
    )
    sm_arn = _create_state_machine(ctx, sm_name, definition, role_arn)

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]

    task_token = _poll_for_task_token(ctx, activity_arn)
    assert task_token, "never received a task token from GetActivityTask"

    code, message = _refusal(lambda: sfn.send_task_success(taskToken=task_token, output="not-valid-json{{{"))
    assert code == "InvalidOutput", f"expected InvalidOutput, got {code!r}"
    expected_message = "Invalid Output: 'not-valid-json{{{' is not valid JSON."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # effect absent, via an independent read at the destination: the execution must still be
    # RUNNING -- SendTaskSuccess with malformed output must not have completed it.
    desc = sfn.describe_execution(executionArn=exec_arn)
    assert desc["status"] == "RUNNING", (
        f"execution should still be RUNNING after a rejected SendTaskSuccess, got {desc['status']!r}"
    )

    # The task must still be outstanding: a heartbeat on the same token must succeed.
    sfn.send_task_heartbeat(taskToken=task_token)

    # Restore: the identical call with valid output now completes the task, and the execution
    # reaches SUCCEEDED -- an independent read confirming the earlier rejection did not wedge it.
    sfn.send_task_success(taskToken=task_token, output="{}")
    desc = _poll_execution_status(ctx, exec_arn, timeout_s=30.0)
    assert desc["status"] == "SUCCEEDED", f"expected SUCCEEDED after a valid SendTaskSuccess, got {desc['status']!r}"


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


def _poll_for_task_token(ctx, activity_arn, attempts=3):
    sfn = ctx.client("stepfunctions")
    for _ in range(attempts):
        resp = sfn.get_activity_task(activityArn=activity_arn, workerName=ctx.unique_name("worker-"))
        token = resp.get("taskToken")
        if token:
            return token
        time.sleep(1.0)
    return None


def _poll_execution_status(ctx, execution_arn, *, timeout_s=30.0, interval_s=1.5):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    desc = sfn.describe_execution(executionArn=execution_arn)
    while desc["status"] == "RUNNING" and time.monotonic() < deadline:
        time.sleep(interval_s)
        desc = sfn.describe_execution(executionArn=execution_arn)
    return desc


def _create_state_machine(ctx, name, definition, role_arn, attempts=15, interval_s=2.0):
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    last_err = None
    for _ in range(attempts):
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )
            sm_arn = resp["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
            return sm_arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                # the trust policy has not propagated to CreateStateMachine's authorizer yet
                last_err = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_err


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
