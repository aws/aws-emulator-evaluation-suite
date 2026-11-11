"""task-token-heartbeat-timeout-catcher-order-decides-winner."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-token-heartbeat-timeout-catcher-order-decides-winner"
GROUP = "task-token-lifecycle"
SERVICES = ["lambda", "stepfunctions"]

_HEARTBEAT_SECONDS = 5
_HEARTBEAT_TIMEOUT_ERROR = "States.HeartbeatTimeout"
_TIMEOUT_ERROR = "States.Timeout"

_SILENT_CODE = (
    "def handler(event, context):\n"
    "    # Intentionally never calls SendTaskHeartbeat/SendTaskSuccess on the token.\n"
    "    return {'received': True, 'token_present': 'token' in event}\n"
)


def _label(error_name):
    return "CaughtBy" + error_name.replace(".", "")


def _definition(fn_arn, sfn_role_arn, first_error, second_error):
    return {
        "Comment": "waitForTaskToken, caught by both heartbeat error names, first vs second",
        "StartAt": "WaitForToken",
        "States": {
            "WaitForToken": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke.waitForTaskToken",
                "Parameters": {
                    "FunctionName": fn_arn,
                    "Payload": {"token.$": "$$.Task.Token"},
                },
                "HeartbeatSeconds": _HEARTBEAT_SECONDS,
                # The execution role was just created moments ago; IAM's eventual consistency
                # means Step Functions may not yet be able to assume it, surfacing as
                # States.TaskFailed on the very first attempt. Retry that specific error only, so
                # the heartbeat timeout this check exercises is never retried away.
                "Retry": [
                    {
                        "ErrorEquals": ["States.TaskFailed"],
                        "IntervalSeconds": 2,
                        "MaxAttempts": 5,
                        "BackoffRate": 2.0,
                    }
                ],
                "Catch": [
                    {"ErrorEquals": [first_error], "Next": _label(first_error)},
                    {"ErrorEquals": [second_error], "Next": _label(second_error)},
                ],
                "End": True,
            },
            _label(_HEARTBEAT_TIMEOUT_ERROR): {
                "Type": "Pass", "Result": "heartbeat-timeout-catcher-won", "End": True,
            },
            _label(_TIMEOUT_ERROR): {
                "Type": "Pass", "Result": "timeout-catcher-won", "End": True,
            },
        },
    }


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A lambda:invoke.waitForTaskToken heartbeat timeout matches both
    States.HeartbeatTimeout and States.Timeout catchers; catcher order decides the winner.
    """
    lambda_role_arn = _create_role(
        ctx, "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": ["states:SendTaskHeartbeat", "states:SendTaskSuccess"],
          "Resource": "*"}],
    )
    sfn_role_arn = _create_role(
        ctx, "states.amazonaws.com",
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}],
    )
    fn_arn = _create_lambda_function(ctx, _SILENT_CODE, lambda_role_arn)

    sm_heartbeat_first = _create_state_machine(
        ctx, _definition(fn_arn, sfn_role_arn, _HEARTBEAT_TIMEOUT_ERROR, _TIMEOUT_ERROR),
        sfn_role_arn,
    )
    sm_timeout_first = _create_state_machine(
        ctx, _definition(fn_arn, sfn_role_arn, _TIMEOUT_ERROR, _HEARTBEAT_TIMEOUT_ERROR),
        sfn_role_arn,
    )

    out_heartbeat_first = _run_and_get_output(ctx, sm_heartbeat_first)
    assert out_heartbeat_first == "heartbeat-timeout-catcher-won", (
        f"with States.HeartbeatTimeout listed first in Catch, the execution output was "
        f"{out_heartbeat_first!r}, expected the first-listed catcher to win"
    )

    out_timeout_first = _run_and_get_output(ctx, sm_timeout_first)
    assert out_timeout_first == "timeout-catcher-won", (
        f"with States.Timeout listed first in Catch, the execution output was "
        f"{out_timeout_first!r}, expected the first-listed catcher to win"
    )


def _run_and_get_output(ctx, sm_arn):
    exec_arn = _start_execution(ctx, sm_arn, {})
    final = _wait_execution_terminal(ctx, exec_arn, timeout_s=90)
    assert final["status"] == "SUCCEEDED", (
        f"a matched Catch must let the execution finish successfully, got "
        f"status={final['status']!r}: {final.get('error')!r} / {final.get('cause')!r}"
    )
    return json.loads(final["output"])


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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
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
    last_err = None
    for _ in range(12):
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                MemorySize=128,
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = e
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_err
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    resp = sfn.create_state_machine(
        name=name,
        definition=json.dumps(definition),
        roleArn=role_arn,
        type="STANDARD",
        tags=[{"key": "sim2real:managed", "value": "true"}],
    )
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, input_dict):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-exec-")
    resp = sfn.start_execution(stateMachineArn=sm_arn, name=name, input=json.dumps(input_dict))
    return resp["executionArn"]


def _wait_execution_terminal(ctx, exec_arn, timeout_s=90, poll_s=2):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    desc = sfn.describe_execution(executionArn=exec_arn)
    while desc["status"] == "RUNNING" and time.monotonic() < deadline:
        time.sleep(poll_s)
        desc = sfn.describe_execution(executionArn=exec_arn)
    if desc["status"] == "RUNNING":
        raise AssertionError(f"execution still RUNNING after {timeout_s}s")
    return desc


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                     budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A Lambda invocation's buffered log stream can flush after delete_function and recreate the
    group, so a single delete is not a teardown.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still present after {budget_s}s of deletes; "
                    f"{absent} clean reads"
                )
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
