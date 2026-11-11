"""sfn-task-token-heartbeat-timeout-fails-execution."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-task-token-heartbeat-timeout-fails-execution"
GROUP = "task-token-callback"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A waitForTaskToken Task with HeartbeatSeconds set fails the execution with a
    terminal States.Timeout when the invoked Lambda never sends a heartbeat or callback."""
    lambda_role_arn = _create_role(ctx, "sfn-behav-lam-role-", "lambda.amazonaws.com", {})
    fn = _create_lambda(
        ctx,
        "sfn-behav-fn-",
        lambda_role_arn,
        (
            "def handler(event, context):\n"
            "    # Deliberately never call SendTaskHeartbeat/SendTaskSuccess/SendTaskFailure.\n"
            "    return {'received': True}\n"
        ),
    )
    sfn_role_arn = _create_role(
        ctx,
        "sfn-behav-sfn-role-",
        "states.amazonaws.com",
        {
            "invoke-lambda": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn["arn"]}
                ],
            }
        },
    )
    definition = {
        "StartAt": "WaitForHeartbeat",
        "States": {
            "WaitForHeartbeat": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke.waitForTaskToken",
                "HeartbeatSeconds": 5,
                "TimeoutSeconds": 300,
                "Parameters": {
                    "FunctionName": fn["arn"],
                    "Payload": {"Token.$": "$$.Task.Token"},
                },
                # The execution role was just created moments ago; IAM's eventual
                # consistency means Step Functions may not yet be able to assume it,
                # surfacing as States.TaskFailed with an "is not authorized to assume
                # the provided role" cause on the very first attempt. Retry that
                # specific error only, so a genuine States.HeartbeatTimeout (the thing
                # this check is actually exercising) is never retried away.
                "Retry": [
                    {
                        "ErrorEquals": ["States.TaskFailed"],
                        "IntervalSeconds": 2,
                        "MaxAttempts": 4,
                        "BackoffRate": 2.0,
                    }
                ],
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, "sfn-behav-sm-", sfn_role_arn, definition)

    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({}))["executionArn"]

    # HeartbeatSeconds=5, give a generous margin above that before treating it as stuck.
    final = _poll_execution(sfn, exec_arn, timeout_s=90.0)
    assert final["status"] == "FAILED", f"unexpected status {final['status']}: {final}"
    # States.HeartbeatTimeout is the error name usable inside Catch/Retry blocks; the
    # terminal execution-level error Step Functions records for a missed heartbeat is
    # States.Timeout (same family as a TimeoutSeconds breach).
    assert final["error"] == "States.Timeout", final


def _trust_policy(service: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
    }


def _create_role(ctx, name_prefix: str, trust_service: str, inline_policies: dict[str, dict]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_prefix)
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_trust_policy(trust_service)),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        for pname in inline_policies:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for pname, doc in inline_policies.items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
    return role_arn


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda(ctx, name_prefix: str, role_arn: str, code: str, timeout: int = 30) -> dict[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name(name_prefix)
    zip_bytes = _lambda_zip(code)
    fn_arn = None
    last_err = None
    for _ in range(15):
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Publish=True,
                Tags={"sim2real": CHECK},
            )
            fn_arn = resp["FunctionArn"]
            break
        except ClientError as e:
            if e.response["Error"]["Code"] in ("InvalidParameterValueException", "AccessDeniedException"):
                last_err = e
                time.sleep(2.0)
                continue
            raise
    if fn_arn is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return {"name": fn_name, "arn": fn_arn}


def _create_state_machine(ctx, name_prefix: str, role_arn: str, definition: dict) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(name_prefix)
    sm_arn = None
    last_err = None
    for _ in range(15):
        try:
            sm_arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                last_err = e
                time.sleep(2.0)
                continue
            raise
    if sm_arn is None:
        raise last_err
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
    return sm_arn


def _poll_execution(sfn, execution_arn: str, timeout_s: float = 90.0, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    resp = None
    while time.monotonic() < deadline:
        resp = sfn.describe_execution(executionArn=execution_arn)
        if resp["status"] != "RUNNING":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"execution stuck RUNNING after {timeout_s}s: {resp}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
