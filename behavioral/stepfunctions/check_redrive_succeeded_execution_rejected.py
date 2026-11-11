"""redrive-succeeded-execution-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-succeeded-execution-rejected"
GROUP = "ordering"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RedriveExecution on a SUCCEEDED execution fails ExecutionNotRedrivable with the exact message and
    leaves it SUCCEEDED with redriveCount 0; a FAILED execution is redriven first."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    activity_arn = _create_activity(ctx)
    pc_definition = json.dumps(
        {
            "StartAt": "DoWork",
            "States": {
                "DoWork": {"Type": "Task", "Resource": activity_arn, "Next": "Done"},
                "Done": {"Type": "Succeed"},
            },
        }
    )
    pc_sm_arn = _create_state_machine(
        ctx, sfn, ctx.unique_name("sim2real-behav-redriverej-pc-"), pc_definition, role_arn
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=pc_sm_arn))
    pc_exec_arn = sfn.start_execution(
        stateMachineArn=pc_sm_arn, name=ctx.unique_name("exec-pc-")
    )["executionArn"]

    pc_token = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_failure(taskToken=pc_token, error="ProbeError", cause="induced failure for positive control")

    pc_failed = _poll_until(
        lambda: sfn.describe_execution(executionArn=pc_exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
        interval_s=1.0,
    )
    assert pc_failed["status"] == "FAILED", f"positive control: expected FAILED, got {pc_failed['status']}"

    sfn.redrive_execution(executionArn=pc_exec_arn)

    pc_resumed = _poll_until(
        lambda: sfn.describe_execution(executionArn=pc_exec_arn),
        lambda d: d.get("redriveCount", 0) == 1,
        timeout_s=15.0,
        interval_s=1.0,
    )
    assert pc_resumed["status"] == "RUNNING", (
        f"positive control: expected RUNNING after a successful redrive, got {pc_resumed['status']}"
    )

    pc_token2 = _poll_activity_task(ctx, activity_arn)
    sfn.send_task_success(taskToken=pc_token2, output=json.dumps({"ok": True}))

    pc_final = _poll_until(
        lambda: sfn.describe_execution(executionArn=pc_exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
        interval_s=1.0,
    )
    assert pc_final["status"] == "SUCCEEDED", f"positive control: expected SUCCEEDED, got {pc_final}"

    name = ctx.unique_name("sim2real-behav-redriverej-")
    definition = json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Succeed"}}})
    sm_arn = _create_state_machine(ctx, sfn, name, definition, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, name=ctx.unique_name("exec-"))["executionArn"]

    _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn)["status"],
        lambda s: s == "SUCCEEDED",
        timeout_s=30.0,
        interval_s=1.0,
    )

    code, message = _error(lambda: sfn.redrive_execution(executionArn=exec_arn))
    assert code == "ExecutionNotRedrivable", f"expected ExecutionNotRedrivable, got {code}"
    expected = f"Execution {exec_arn} invalid for redrive as: Execution is SUCCEEDED and cannot be redriven"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    desc = sfn.describe_execution(executionArn=exec_arn)
    assert desc["status"] == "SUCCEEDED", "status must remain SUCCEEDED after a rejected redrive"
    assert desc.get("redriveCount", 0) == 0, "redriveCount must not increment on a rejected redrive"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_activity(ctx):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-redriverej-activity-")
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real-check", "value": CHECK}])["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _poll_activity_task(ctx, activity_arn, timeout_s=60.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        token = sfn.get_activity_task(activityArn=activity_arn, workerName="sim2real-behav").get("taskToken")
        if token:
            return token
    raise AssertionError(f"never received an activity task within {timeout_s}s")


def _create_sfn_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = list(extra_statements or [])
    if not statements:
        statements = [{"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": "*"}]
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_state_machine(ctx, sfn, name, definition, role_arn, type_="STANDARD"):
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type=type_,
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )
            return resp["stateMachineArn"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create state machine after IAM propagation wait: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
