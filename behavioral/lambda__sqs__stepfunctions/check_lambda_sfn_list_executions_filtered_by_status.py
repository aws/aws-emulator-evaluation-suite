"""lambda-sfn-list-executions-filtered-by-status."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sfn-list-executions-filtered-by-status"
GROUP = "lambda-sfn-chaining"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListExecutions with statusFilter, called from a Lambda, returns only matching executions: the
    SUCCEEDED run appears under SUCCEEDED but not FAILED, and the FAILED run the reverse."""
    sfn = ctx.client("stepfunctions")

    sfn_role_name, sfn_role_arn = _create_role(ctx, "states.amazonaws.com", {})
    definition = {
        "StartAt": "Choice",
        "States": {
            "Choice": {
                "Type": "Choice",
                "Choices": [{"Variable": "$.succeed", "BooleanEquals": True, "Next": "Ok"}],
                "Default": "Bad",
            },
            "Ok": {"Type": "Pass", "End": True},
            "Bad": {"Type": "Fail", "Error": "IntentionalFailure", "Cause": "test"},
        },
    }
    sm_arn = _create_state_machine(ctx, sfn_role_arn, definition)

    ok_name = ctx.unique_name("sim2real-exec-ok-")
    bad_name = ctx.unique_name("sim2real-exec-bad-")
    ok_started = sfn.start_execution(stateMachineArn=sm_arn, name=ok_name, input=json.dumps({"succeed": True}))
    bad_started = sfn.start_execution(stateMachineArn=sm_arn, name=bad_name, input=json.dumps({"succeed": False}))

    ok_desc = _wait_execution_terminal(ctx, ok_started["executionArn"])
    bad_desc = _wait_execution_terminal(ctx, bad_started["executionArn"])
    assert ok_desc["status"] == "SUCCEEDED", ok_desc
    assert bad_desc["status"] == "FAILED", bad_desc

    lambda_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "states:ListExecutions", "Resource": sm_arn}],
    }
    lambda_role_name, lambda_role_arn = _create_role(
        ctx, "lambda.amazonaws.com", {"list-executions": lambda_policy}
    )
    _attach_basic_execution(ctx, lambda_role_name)

    code = """
import boto3
import os

def handler(event, context):
    sfn = boto3.client("stepfunctions")
    resp = sfn.list_executions(stateMachineArn=os.environ["SM_ARN"], statusFilter=event["statusFilter"])
    return {"names": [e["name"] for e in resp["executions"]]}
"""
    fn_name, _fn_arn = _create_function(ctx, lambda_role_arn, code, env={"SM_ARN": sm_arn}, timeout=30)

    # ListExecutions' statusFilter index is eventually consistent: DescribeExecution already
    # reports the terminal status above, but a filtered list made immediately after can still
    # lag by a few seconds, so poll (bounded) rather than asserting on the first response.
    succeeded_body = _invoke_until(ctx, fn_name, {"statusFilter": "SUCCEEDED"}, ok_name)
    assert ok_name in succeeded_body["names"], succeeded_body
    assert bad_name not in succeeded_body["names"], succeeded_body

    failed_body = _invoke_until(ctx, fn_name, {"statusFilter": "FAILED"}, bad_name)
    assert bad_name in failed_body["names"], failed_body
    assert ok_name not in failed_body["names"], failed_body


def _create_role(ctx, trust_service: str, inline_policies: dict[str, dict]) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    for pname, pdoc in inline_policies.items():
        iam.put_role_policy(RoleName=name, PolicyName=pname, PolicyDocument=json.dumps(pdoc))
    return name, arn


def _attach_basic_execution(ctx, role_name: str) -> None:
    ctx.client("iam").attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=p)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for p in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _zip_code(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(filename, code)
    return buf.getvalue()


def _wait_function_active(ctx, name: str, timeout_s: float = 60.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        if cfg["State"] == "Failed":
            raise AssertionError(f"lambda function {name} failed to activate: {cfg}")
        time.sleep(2)
    raise AssertionError(f"lambda function {name} did not become Active within {timeout_s}s")


def _create_function(
    ctx, role_arn: str, code: str, handler: str = "index.handler", env: dict | None = None, timeout: int = 30
) -> tuple[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _zip_code(code)
    last_err: Exception | None = None
    deadline = time.monotonic() + 60
    resp: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"create_function never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return name, resp["FunctionArn"]


def _create_state_machine(ctx, role_arn: str, definition: dict, name: str | None = None) -> str:
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-sm-")
    last_err: Exception | None = None
    deadline = time.monotonic() + 60
    resp: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                tags=[{"key": "sim2real:managed", "value": "true"}],
            )
            break
        except sfn.exceptions.AccessDeniedException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"create_state_machine never succeeded: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _wait_execution_terminal(ctx, exec_arn: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] != "RUNNING":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} did not reach terminal state within {timeout_s}s")


def _invoke_retry(ctx, function_name: str, payload: dict, timeout_s: float = 60.0) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode())
        body = json.loads(resp["Payload"].read())
        if resp.get("FunctionError"):
            if "AccessDenied" in json.dumps(body):
                last_err = AssertionError(body)
                time.sleep(3)
                continue
            raise AssertionError(f"lambda invoke failed: {body}")
        return body
    raise AssertionError(f"lambda invoke never succeeded: {last_err}")


def _invoke_until(
    ctx, function_name: str, payload: dict, expect_name: str, timeout_s: float = 30.0
) -> dict:
    deadline = time.monotonic() + timeout_s
    body = _invoke_retry(ctx, function_name, payload)
    while expect_name not in body["names"] and time.monotonic() < deadline:
        time.sleep(1.0)
        body = _invoke_retry(ctx, function_name, payload)
    return body


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
