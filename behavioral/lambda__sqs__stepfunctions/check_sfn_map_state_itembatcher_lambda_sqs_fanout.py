"""sfn-map-state-itembatcher-lambda-sqs-fanout."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sfn-map-state-itembatcher-lambda-sqs-fanout"
GROUP = "lambda-sfn-chaining"
SERVICES = ["lambda", "stepfunctions", "sqs"]

_MGMT_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Distributed Map with ItemBatcher size 2 over 4 items SUCCEEDS and sends exactly 2 SQS messages, one
    per batch, whose transformed values are exactly [10, 20, 30, 40].
    """
    ctx.client("sqs")
    sfn = ctx.client("stepfunctions")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    queue_url, queue_arn = _create_queue(ctx)

    lambda_code = """
def handler(event, context):
    items = event["Items"]
    return {"multiplied": [i * 10 for i in items]}
"""
    lambda_role_name, lambda_role_arn = _create_role(ctx, "lambda.amazonaws.com", {})
    _attach_basic_execution(ctx, lambda_role_name)
    fn_name, fn_arn = _create_function(ctx, lambda_role_arn, lambda_code)

    sm_name = ctx.unique_name("sim2real-sm-")
    predicted_sm_arn = f"arn:aws:states:{ctx.region}:{account_id}:stateMachine:{sm_name}"

    sfn_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "states:StartExecution", "Resource": predicted_sm_arn},
            {
                "Effect": "Allow",
                "Action": "states:DescribeExecution",
                "Resource": _execution_resource_pattern(predicted_sm_arn),
            },
            {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn},
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
        ],
    }
    _sfn_role_name, sfn_role_arn = _create_role(ctx, "states.amazonaws.com", {"map": sfn_policy})

    definition = {
        "StartAt": "BatchMap",
        "States": {
            "BatchMap": {
                "Type": "Map",
                "ItemsPath": "$.items",
                "ItemBatcher": {"MaxItemsPerBatch": 2},
                "MaxConcurrency": 2,
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
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
                },
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, sfn_role_arn, definition, name=sm_name)
    assert sm_arn == predicted_sm_arn, (sm_arn, predicted_sm_arn)

    started = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({"items": [1, 2, 3, 4]}))
    desc = _wait_execution_terminal(ctx, started["executionArn"], timeout_s=180, interval_s=3)
    retry_deadline = time.monotonic() + 90
    while desc["status"] != "SUCCEEDED" and time.monotonic() < retry_deadline:
        blob = f"{desc.get('error', '')} {desc.get('cause', '')}"
        assert "AccessDenied" in blob or "not authorized" in blob, desc
        # Freshly-created execution role permissions had not propagated when the Map's
        # first child execution ran; retry with a bounded backoff until the role settles.
        time.sleep(5)
        started = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({"items": [1, 2, 3, 4]}))
        desc = _wait_execution_terminal(ctx, started["executionArn"], timeout_s=180, interval_s=3)
    assert desc["status"] == "SUCCEEDED", desc

    messages = _receive_all(ctx, queue_url, max_messages=10, wait_s=15)
    assert len(messages) == 2, messages

    multiplied: list[int] = []
    for m in messages:
        body = json.loads(m["Body"])
        multiplied.extend(body["multiplied"])
    assert sorted(multiplied) == [10, 20, 30, 40], multiplied


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
        Tags=[{"Key": k, "Value": v} for k, v in _MGMT_TAGS.items()],
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
                Tags=_MGMT_TAGS,
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
                tags=[{"key": k, "value": v} for k, v in _MGMT_TAGS.items()],
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


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-q-"), tags=_MGMT_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _receive_all(ctx, queue_url: str, max_messages: int = 10, wait_s: int = 5) -> list[dict]:
    sqs = ctx.client("sqs")
    out: list[dict] = []
    deadline = time.monotonic() + wait_s + 10
    while len(out) < max_messages and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=min(wait_s, 20)
        )
        batch = resp.get("Messages", [])
        if not batch:
            break
        for m in batch:
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
