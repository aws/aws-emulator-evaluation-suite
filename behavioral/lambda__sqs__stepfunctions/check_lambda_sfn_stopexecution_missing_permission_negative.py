"""lambda-sfn-stopexecution-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sfn-stopexecution-missing-permission-negative"
GROUP = "lambda-sfn-chaining"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role lacks states:StopExecution gets AccessDeniedException from StopExecution and the
    execution stays RUNNING; a Lambda whose role has the permission aborts a second execution (ABORTED).
    """
    sfn = ctx.client("stepfunctions")

    sfn_role_name, sfn_role_arn = _create_role(ctx, "states.amazonaws.com", {})
    definition = {"StartAt": "LongWait", "States": {"LongWait": {"Type": "Wait", "Seconds": 300, "End": True}}}
    sm_arn = _create_state_machine(ctx, sfn_role_arn, definition)

    started_neg = sfn.start_execution(stateMachineArn=sm_arn)
    neg_exec_arn = started_neg["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, neg_exec_arn))

    started_pos = sfn.start_execution(stateMachineArn=sm_arn)
    pos_exec_arn = started_pos["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, pos_exec_arn))

    code = """
import boto3
import botocore.exceptions

def handler(event, context):
    sfn = boto3.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=event["executionArn"], error="StoppedByLambda", cause="test")
        return {"errorCode": None}
    except botocore.exceptions.ClientError as e:
        return {"errorCode": e.response["Error"]["Code"]}
"""

    # --- No-permission role: no stepfunctions access at all beyond basic execution. ---
    noperm_role_name, noperm_role_arn = _create_role(ctx, "lambda.amazonaws.com", {})
    _attach_basic_execution(ctx, noperm_role_name)
    noperm_fn_name, _noperm_arn = _create_function(ctx, noperm_role_arn, code, timeout=30)

    body = _invoke_retry(ctx, noperm_fn_name, {"executionArn": neg_exec_arn})
    assert body["errorCode"] == "AccessDeniedException", body

    still_running = sfn.describe_execution(executionArn=neg_exec_arn)
    assert still_running["status"] == "RUNNING", still_running

    # --- Positive control: role WITH states:StopExecution succeeds on a different execution. ---
    perm_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "states:StopExecution", "Resource": _execution_resource_pattern(sm_arn)}
        ],
    }
    perm_role_name, perm_role_arn = _create_role(ctx, "lambda.amazonaws.com", {"stop": perm_policy})
    _attach_basic_execution(ctx, perm_role_name)
    perm_fn_name, _perm_arn = _create_function(ctx, perm_role_arn, code, timeout=30)

    # IAM policy propagation for the newly-attached inline policy can lag a few
    # seconds; poll the actual outcome (not a fixed sleep) until it clears.
    ok_body = {"errorCode": "AccessDeniedException"}
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline and ok_body["errorCode"] == "AccessDeniedException":
        ok_body = _invoke_retry(ctx, perm_fn_name, {"executionArn": pos_exec_arn})
        if ok_body["errorCode"] == "AccessDeniedException":
            time.sleep(3)
    assert ok_body["errorCode"] is None, ok_body

    deadline = time.monotonic() + 30
    final_desc = None
    while time.monotonic() < deadline:
        final_desc = sfn.describe_execution(executionArn=pos_exec_arn)
        if final_desc["status"] != "RUNNING":
            break
        time.sleep(2)
    assert final_desc is not None and final_desc["status"] == "ABORTED", final_desc


def _best_effort_stop(ctx, exec_arn: str) -> None:
    try:
        ctx.client("stepfunctions").stop_execution(executionArn=exec_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _create_role(ctx, trust_service: str, inline_policies: dict[str, dict]) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
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


def _execution_resource_pattern(sm_arn: str) -> str:
    return sm_arn.replace(":stateMachine:", ":execution:") + ":*"


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
                name=name, definition=json.dumps(definition), roleArn=role_arn
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


def _invoke_retry(ctx, function_name: str, payload: dict, timeout_s: float = 60.0) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode())
        body = json.loads(resp["Payload"].read())
        if resp.get("FunctionError"):
            raise AssertionError(f"lambda invoke crashed unexpectedly: {body}")
        return body
    raise AssertionError(f"lambda invoke never succeeded: {last_err}")


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
