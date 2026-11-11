"""lambda-waitfortasktoken-heartbeat-timeout-history-event."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-waitfortasktoken-heartbeat-timeout-history-event"
GROUP = "execution-history"
SERVICES = ["lambda", "stepfunctions"]


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html
@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A lambda:invoke.waitForTaskToken task whose heartbeat window expires records the
    generic TaskTimedOut history event, naming the lambda resource; a sibling that
    heartbeats in time has none."""
    lambda_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": ["states:SendTaskHeartbeat", "states:SendTaskSuccess"], "Resource": "*"}],
    )
    sfn_role_arn = _create_role(
        ctx, "states.amazonaws.com", [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}]
    )

    heartbeat_code = (
        "import time\n"
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    token = event['token']\n"
        "    client = boto3.client('stepfunctions')\n"
        "    time.sleep(3)\n"
        "    client.send_task_heartbeat(taskToken=token)\n"
        "    time.sleep(3)\n"
        "    client.send_task_success(taskToken=token, output='{\"done\": true}')\n"
        "    return {'sent': True}\n"
    )
    silent_code = (
        "def handler(event, context):\n"
        "    # Intentionally never calls SendTaskHeartbeat/SendTaskSuccess on the token.\n"
        "    return {'received': True}\n"
    )
    fn_heartbeat_arn = _create_lambda_function(ctx, heartbeat_code, lambda_role_arn)
    fn_silent_arn = _create_lambda_function(ctx, silent_code, lambda_role_arn)

    def _definition(fn_arn):
        return {
            "StartAt": "WaitForToken",
            "States": {
                "WaitForToken": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke.waitForTaskToken",
                    "Parameters": {"FunctionName": fn_arn, "Payload": {"token.$": "$$.Task.Token"}},
                    "HeartbeatSeconds": 5,
                    # The execution role was just created moments ago; IAM's eventual
                    # consistency means Step Functions may not yet be able to invoke the
                    # Lambda through it, surfacing as States.TaskFailed on the very first
                    # attempt. Retry that specific error only, so the heartbeat outcome
                    # this check exercises is never retried away.
                    "Retry": [
                        {"ErrorEquals": ["States.TaskFailed"], "IntervalSeconds": 2, "MaxAttempts": 4, "BackoffRate": 2.0}
                    ],
                    "End": True,
                }
            },
        }

    sm_ok_arn = _create_state_machine(ctx, _definition(fn_heartbeat_arn), sfn_role_arn)
    sm_bad_arn = _create_state_machine(ctx, _definition(fn_silent_arn), sfn_role_arn)

    sfn = ctx.client("stepfunctions")

    # --- positive control: identical wiring, Lambda heartbeats then succeeds ---
    exec_ok = sfn.start_execution(stateMachineArn=sm_ok_arn, input="{}")["executionArn"]
    desc_ok = _wait_execution_terminal(ctx, exec_ok, timeout_s=90)
    assert desc_ok["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {desc_ok['status']}: {desc_ok.get('error')}"
    types_ok = [e["type"] for e in sfn.get_execution_history(executionArn=exec_ok)["events"]]
    assert "TaskTimedOut" not in types_ok, f"a heartbeat sent in time must leave no TaskTimedOut event, got {types_ok}"

    # --- negative: identical wiring, Lambda never heartbeats -> States.Timeout ---
    exec_bad = sfn.start_execution(stateMachineArn=sm_bad_arn, input="{}")["executionArn"]
    desc_bad = _wait_execution_terminal(ctx, exec_bad, timeout_s=90)
    assert desc_bad["status"] == "FAILED", f"expected FAILED, got {desc_bad['status']}"
    assert desc_bad.get("error") == "States.Timeout", f"unexpected error: {desc_bad.get('error')!r}"

    events_bad = sfn.get_execution_history(executionArn=exec_bad)["events"]
    types_bad = [e["type"] for e in events_bad]
    # The waitForTaskToken callback pattern records the GENERIC TaskTimedOut event, not the
    # LambdaFunctionTimedOut that the optimized (non-callback) Lambda integration would use.
    assert "TaskTimedOut" in types_bad, f"expected TaskTimedOut in the history of a heartbeat timeout, got {types_bad}"
    assert "LambdaFunctionTimedOut" not in types_bad, (
        f"a waitForTaskToken heartbeat timeout must not use the optimized-integration event name, got {types_bad}"
    )
    timed_out = next(e for e in events_bad if e["type"] == "TaskTimedOut")
    detail = timed_out.get("taskTimedOutEventDetails", {})
    assert detail.get("resourceType") == "lambda", f"unexpected timeout detail: {detail!r}"
    assert detail.get("resource") == "invoke.waitForTaskToken", f"unexpected timeout detail: {detail!r}"
    assert detail.get("error") == "States.Timeout", f"unexpected timeout detail: {detail!r}"

    # effect absent: an independent read confirms the failed execution stays FAILED
    desc_after = sfn.describe_execution(executionArn=exec_bad)
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
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    statements = [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"}
    ] + extra_statements
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements})
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_lambda_function(ctx, code, role_arn, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _zip_bytes(code)
    resp = None
    last_err = None
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
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
            if e.response["Error"]["Code"] in ("InvalidParameterValueException", "AccessDeniedException"):
                last_err = e
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_err
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    arn = None
    last_err = None
    for _ in range(12):
        try:
            resp = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real:managed", "value": "true"}],
            )
            arn = resp["stateMachineArn"]
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                last_err = e
                time.sleep(5)
                continue
            raise
    if arn is None:
        raise last_err
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
    return arn


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


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
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
                raise AssertionError(f"log group still present after {budget_s}s of deletes; {absent} clean reads")
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
