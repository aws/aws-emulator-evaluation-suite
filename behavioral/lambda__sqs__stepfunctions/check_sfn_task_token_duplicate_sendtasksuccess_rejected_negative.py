"""sfn-task-token-duplicate-sendtasksuccess-rejected-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-task-token-duplicate-sendtasksuccess-rejected-negative"
GROUP = "task-token-lifecycle"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second SendTaskSuccess for an already-completed task token is rejected, and the
    already-succeeded execution's recorded outcome is left untouched by the replay."""
    lambda_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": "states:SendTaskSuccess", "Resource": "*"}],
    )
    sfn_role_arn = _create_role(
        ctx,
        "states.amazonaws.com",
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}],
    )

    fn_code = (
        "import json\n"
        "import boto3\n"
        "\n"
        "def handler(event, context):\n"
        "    token = event['token']\n"
        "    client = boto3.client('stepfunctions')\n"
        "    client.send_task_success(taskToken=token, output=json.dumps({'token': token}))\n"
        "    return {'sent': True}\n"
    )
    fn_arn = _create_lambda_function(ctx, fn_code, lambda_role_arn)

    definition = {
        "StartAt": "WaitForToken",
        "States": {
            "WaitForToken": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke.waitForTaskToken",
                "Parameters": {
                    "FunctionName": fn_arn,
                    "Payload": {"token.$": "$$.Task.Token"},
                },
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, sfn_role_arn)

    # positive control: the first SendTaskSuccess call completes the execution normally.
    # The two IAM roles above are eventually consistent for their first use (the sfn role's
    # lambda:InvokeFunction grant in particular), so retry a fresh execution on a bounded
    # deadline instead of sleeping blindly before starting one.
    exec_arn, desc = _run_until_succeeded(ctx, sm_arn, deadline_s=90)
    assert desc["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {desc['status']}: {desc.get('error')}"
    output = json.loads(desc["output"])
    token = output["token"]

    # negative: replaying SendTaskSuccess against the now-closed token is rejected.
    sfn = ctx.client("stepfunctions")
    error = _expect_error(
        lambda: sfn.send_task_success(taskToken=token, output=json.dumps({"token": token}))
    )
    assert error.get("Code") == "TaskTimedOut", f"expected TaskTimedOut, got {error!r}"
    expected_message = "Task Timed Out: 'Provided task does not exist anymore'"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # effect absent: the execution's recorded outcome is unchanged by the rejected replay.
    desc_after = sfn.describe_execution(executionArn=exec_arn)
    assert desc_after["status"] == "SUCCEEDED", desc_after
    assert json.loads(desc_after["output"]) == output, desc_after


# ===== helpers =====
def _expect_error(fn):
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(ctx, principal, extra_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ] + extra_statements
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_lambda_function(ctx, code, role_arn, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _zip_bytes(code)
    resp = None
    deadline = time.monotonic() + 60.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left() - 5.0)
    while True:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    deadline = time.monotonic() + 30
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD"
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                last_err = e
                time.sleep(2)
                continue
            raise
    if resp is None:
        raise last_err
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, input_dict):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-exec-")
    resp = sfn.start_execution(stateMachineArn=sm_arn, name=name, input=json.dumps(input_dict))
    return resp["executionArn"]


def _wait_execution_terminal(ctx, exec_arn, timeout_s=90, poll_s=3):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    desc = sfn.describe_execution(executionArn=exec_arn)
    while desc["status"] == "RUNNING" and time.monotonic() < deadline:
        time.sleep(poll_s)
        desc = sfn.describe_execution(executionArn=exec_arn)
    if desc["status"] == "RUNNING":
        raise AssertionError(f"execution still RUNNING after {timeout_s}s")
    return desc


def _run_until_succeeded(ctx, sm_arn, deadline_s=90, poll_s=3, retry_backoff_s=5):
    """Start executions until one reaches SUCCEEDED, bounded by deadline_s.

    The sfn role's lambda:InvokeFunction grant can take a few seconds to propagate; a
    fresh execution started before that lands fails outright (no Retry on the Task
    state), so retry the whole run rather than sleeping once before the first attempt.
    """
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        exec_arn = _start_execution(ctx, sm_arn, {})
        desc = _wait_execution_terminal(ctx, exec_arn, timeout_s=min(30, remaining), poll_s=poll_s)
        if desc["status"] == "SUCCEEDED":
            return exec_arn, desc
        last = desc
        time.sleep(retry_backoff_s)
    raise AssertionError(f"no execution reached SUCCEEDED within {deadline_s}s (last={last!r})")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
