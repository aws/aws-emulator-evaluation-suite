"""sfn-waitfortasktoken-lambda-sendtaskfailure-fails-execution."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-waitfortasktoken-lambda-sendtaskfailure-fails-execution"
GROUP = "task-token-callback"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A waitForTaskToken Task invokes Lambda; Lambda calls SendTaskFailure and the
    execution transitions to FAILED carrying the exact error/cause Lambda reported."""
    lambda_role_arn = _create_role(
        ctx,
        "sfn-behav-lam-role-",
        "lambda.amazonaws.com",
        {
            "send-task-failure": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "states:SendTaskFailure", "Resource": "*"}
                ],
            }
        },
    )
    fn = _create_lambda(
        ctx,
        "sfn-behav-fn-",
        lambda_role_arn,
        (
            "import boto3\n\n"
            "def handler(event, context):\n"
            "    sfn = boto3.client('stepfunctions')\n"
            "    sfn.send_task_failure(\n"
            "        taskToken=event['Token'],\n"
            "        error='LambdaReportedFailure',\n"
            "        cause='simulated failure from lambda',\n"
            "    )\n"
            "    return {'ok': True}\n"
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
        "StartAt": "WaitForCallback",
        "States": {
            "WaitForCallback": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke.waitForTaskToken",
                "Parameters": {
                    "FunctionName": fn["arn"],
                    "Payload": {"Token.$": "$$.Task.Token"},
                },
                # The execution role was just created moments ago; IAM's eventual
                # consistency means Step Functions may not yet be able to assume it,
                # surfacing as States.TaskFailed with an "is not authorized to assume
                # the provided role" cause on the very first attempt. Retry it.
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

    final = _poll_execution(sfn, exec_arn, timeout_s=90.0)
    assert final["status"] == "FAILED", f"unexpected status {final['status']}: {final}"
    assert final["error"] == "LambdaReportedFailure", final
    assert final["cause"] == "simulated failure from lambda", final


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
                Tags={"sim2real:managed": "true"},
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
                tags=[{"key": "sim2real:managed", "value": "true"}],
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
