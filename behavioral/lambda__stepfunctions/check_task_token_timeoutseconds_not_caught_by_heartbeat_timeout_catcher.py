"""task-token-timeoutseconds-not-caught-by-heartbeat-timeout-catcher."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-token-timeoutseconds-not-caught-by-heartbeat-timeout-catcher"
GROUP = "task-token-lifecycle"
SERVICES = ["lambda", "stepfunctions"]

_TASK_TIMEOUT_SECONDS = 5
_TIMEOUT_ERROR = "States.Timeout"
_HEARTBEAT_TIMEOUT_ERROR = "States.HeartbeatTimeout"

_SILENT_CODE = (
    "def handler(event, context):\n"
    "    # Intentionally never calls SendTaskHeartbeat/SendTaskSuccess on the token.\n"
    "    return {'received': True, 'token_present': 'token' in event}\n"
)


def _definition(fn_arn, catch_error_names, catch_next):
    return {
        "Comment": "waitForTaskToken, TimeoutSeconds only, no HeartbeatSeconds",
        "StartAt": "WaitForToken",
        "States": {
            "WaitForToken": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke.waitForTaskToken",
                "Parameters": {
                    "FunctionName": fn_arn,
                    "Payload": {"token.$": "$$.Task.Token"},
                },
                "TimeoutSeconds": _TASK_TIMEOUT_SECONDS,
                # The execution role was just created moments ago; IAM's eventual consistency
                # means Step Functions may not yet be able to assume it, surfacing as
                # States.TaskFailed on the very first attempt. Retry that specific error only, so
                # the TimeoutSeconds breach this check exercises is never retried away.
                "Retry": [
                    {
                        "ErrorEquals": ["States.TaskFailed"],
                        "IntervalSeconds": 2,
                        "MaxAttempts": 5,
                        "BackoffRate": 2.0,
                    }
                ],
                "Catch": [{"ErrorEquals": catch_error_names, "Next": catch_next}],
                "End": True,
            },
            "Caught": {"Type": "Pass", "Result": "caught", "End": True},
        },
    }


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html
@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A lambda:invoke.waitForTaskToken's TimeoutSeconds breach (no HeartbeatSeconds set) is
    NOT matched by a Catch naming only States.HeartbeatTimeout: it fails the execution uncaught
    with States.Timeout. A sibling Catch naming States.Timeout catches the identical wiring.
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

    # Positive control first: the same TimeoutSeconds breach, caught by the error name it
    # actually carries.
    sm_ok = _create_state_machine(
        ctx, _definition(fn_arn, [_TIMEOUT_ERROR], "Caught"), sfn_role_arn,
    )
    exec_ok = _start_execution(ctx, sm_ok, {})
    desc_ok = _wait_execution_terminal(ctx, exec_ok, timeout_s=90)
    assert desc_ok["status"] == "SUCCEEDED", (
        f"a Catch naming States.Timeout must catch its own TimeoutSeconds breach, got "
        f"status={desc_ok['status']!r}: {desc_ok.get('error')!r} / {desc_ok.get('cause')!r}"
    )
    assert json.loads(desc_ok["output"]) == "caught", (
        f"expected the catcher's own output 'caught', got {desc_ok.get('output')!r}"
    )

    # Subject: identical wiring, the Catch names only States.HeartbeatTimeout — a name that
    # applies to a lapsed heartbeat, not to a TimeoutSeconds breach with no heartbeat clock at all.
    sm_bad = _create_state_machine(
        ctx, _definition(fn_arn, [_HEARTBEAT_TIMEOUT_ERROR], "Caught"), sfn_role_arn,
    )
    exec_bad = _start_execution(ctx, sm_bad, {})
    desc_bad = _wait_execution_terminal(ctx, exec_bad, timeout_s=90)
    assert desc_bad["status"] == "FAILED", (
        f"a Catch naming only States.HeartbeatTimeout must not catch a TimeoutSeconds breach, "
        f"got status={desc_bad['status']!r}"
    )
    assert desc_bad.get("error") == _TIMEOUT_ERROR, (
        f"expected the uncaught execution to fail with {_TIMEOUT_ERROR!r}, got "
        f"{desc_bad.get('error')!r}: {desc_bad.get('cause')!r}"
    )
    assert "output" not in desc_bad, (
        f"an uncaught failed execution carries an output: {desc_bad.get('output')!r}"
    )

    # Effect absent: an independent read confirms the failed execution stays FAILED.
    desc_after = ctx.client("stepfunctions").describe_execution(executionArn=exec_bad)
    assert desc_after["status"] == "FAILED", desc_after


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
