"""sfn-lambda-invoke-payload-too-large-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sfn-lambda-invoke-payload-too-large-negative"
GROUP = "lambda-sfn-chaining"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda task returning more than 262,144 bytes FAILS the execution with States.DataLimitExceeded and
    the exact cause, and the SQS-send task never delivers; with a small payload the execution SUCCEEDS and
    exactly one message "ok" arrives.
    """
    ctx.client("sqs")
    sfn = ctx.client("stepfunctions")

    queue_url, queue_arn = _create_queue(ctx)

    lambda_code = """
def handler(event, context):
    if event.get("big"):
        return "x" * 300000
    return "ok"
"""
    lambda_role_name, lambda_role_arn = _create_role(ctx, "lambda.amazonaws.com", {})
    _attach_basic_execution(ctx, lambda_role_name)
    fn_name, fn_arn = _create_function(ctx, lambda_role_arn, lambda_code)

    sfn_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn},
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
        ],
    }
    _sfn_role_name, sfn_role_arn = _create_role(ctx, "states.amazonaws.com", {"pipeline": sfn_policy})

    definition = {
        "StartAt": "InvokeLambda",
        "States": {
            "InvokeLambda": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "OutputPath": "$.Payload",
                "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
                "Next": "SendToQueue",
            },
            "SendToQueue": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage",
                "Parameters": {"QueueUrl": queue_url, "MessageBody.$": "$"},
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, sfn_role_arn, definition)

    # --- Negative run: oversized Lambda output must fail the execution before SendToQueue. ---
    desc_big = _start_execution_with_iam_retry(
        ctx, sfn, sm_arn, {"big": True}, wait_timeout=60, stop_errors=("States.DataLimitExceeded",)
    )
    assert desc_big["status"] == "FAILED", desc_big
    assert desc_big.get("error") == "States.DataLimitExceeded", desc_big
    expected_cause = (
        "The state/task 'lambda' returned a result with a size exceeding "
        "the maximum number of bytes service limit."
    )
    assert desc_big.get("cause") == expected_cause, desc_big.get("cause")

    big_messages = _receive_all(ctx, queue_url, wait_s=5)
    assert big_messages == [], f"pipeline advanced past the data limit failure: {big_messages}"

    # --- Positive control: small Lambda output completes and reaches SQS. ---
    desc_ok = _start_execution_with_iam_retry(ctx, sfn, sm_arn, {"big": False}, wait_timeout=60)
    assert desc_ok["status"] == "SUCCEEDED", desc_ok


    ok_messages = _receive_all(ctx, queue_url, wait_s=10)
    assert len(ok_messages) == 1, ok_messages
    assert ok_messages[0]["Body"] == "ok", ok_messages[0]


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-role-"}],
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
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-fn-"},
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
                name=name, definition=json.dumps(definition), roleArn=role_arn,
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


def _start_execution_with_iam_retry(
    ctx,
    sfn,
    sm_arn: str,
    input_obj: dict,
    wait_timeout: float = 60.0,
    max_attempts: int = 6,
    retry_sleep: float = 8.0,
    stop_errors: tuple[str, ...] = (),
) -> dict:
    """A freshly-created SFN execution role has not always propagated through IAM by
    the time the state machine's first task actually exercises its permissions (the
    create_state_machine retry only covers the control-plane call, not eventual
    consistency of the role's policy on the data plane). If an execution fails with an
    access-denied-flavored error that is not one of the expected `stop_errors`, start a
    fresh execution after a short backoff instead of treating the transient denial as
    the behavior under test.
    """
    last_desc: dict | None = None
    for _ in range(max_attempts):
        started = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(input_obj))
        desc = _wait_execution_terminal(ctx, started["executionArn"], timeout_s=wait_timeout)
        if desc["status"] == "SUCCEEDED" or desc.get("error") in stop_errors:
            return desc
        last_desc = desc
        blob = f"{desc.get('error', '')} {desc.get('cause', '')}"
        if "AccessDenied" in blob or "not authorized" in blob:
            time.sleep(retry_sleep)
            continue
        return desc
    return last_desc


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-q-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _receive_all(ctx, queue_url: str, max_messages: int = 10, wait_s: int = 5) -> list[dict]:
    sqs = ctx.client("sqs")
    out: list[dict] = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=wait_s)
    for m in resp.get("Messages", []):
        out.append(m)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


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
