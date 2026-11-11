"""lambda-sdk-sqs-batch-sendmessage-delivers-all."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-sqs-batch-sendmessage-delivers-all"
GROUP = "sdk-call"
SERVICES = ["events", "lambda", "sqs"]

_HANDLER = """
import boto3

def handler(event, context):
    client = boto3.client('sqs')
    try:
        resp = client.send_message_batch(QueueUrl=event['queue_url'], Entries=event['entries'])
        return {
            'ok': True,
            'successful_ids': sorted(e['Id'] for e in resp.get('Successful', [])),
            'failed': resp.get('Failed', []),
        }
    except Exception as e:
        code = getattr(e, 'response', {}).get('Error', {}).get('Code', str(e))
        return {'ok': False, 'code': code}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda's SendMessageBatch call delivers all batched entries to the target SQS queue."""
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))

    role_arn = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
        "batch-send",
    )
    fn_name = _create_function(ctx, role_arn, _HANDLER, "batch-send")

    entries = [
        {"Id": f"entry-{i}", "MessageBody": f"sim2real-batch-body-{i}"} for i in range(6)
    ]
    body = _poll_until(
        lambda: _invoke(ctx, fn_name, {"queue_url": queue_url, "entries": entries}),
        lambda b: b.get("ok") is True,
        timeout_s=40.0,
        interval_s=3.0,
    )
    assert body["failed"] == [], f"expected no failed entries, got {body['failed']}"
    expected_ids = sorted(e["Id"] for e in entries)
    assert body["successful_ids"] == expected_ids, (
        f"expected successful ids {expected_ids}, got {body['successful_ids']}"
    )

    expected_bodies = {e["MessageBody"] for e in entries}
    received_bodies: set[str] = set()
    receipts: list[str] = []
    deadline = time.monotonic() + 60.0
    while received_bodies != expected_bodies and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            received_bodies.add(m["Body"])
            receipts.append(m["ReceiptHandle"])
    for rh in receipts:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=rh)
    assert received_bodies == expected_bodies, f"missing bodies: {expected_bodies - received_bodies}"


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_LOGS_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_role(ctx: Any, statements: list, suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-behav-role-{suffix}-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY)
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_LOGS_POLICY_ARN)
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline-under-test",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _delete_role(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _zip_handler(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_function(ctx: Any, role_arn: str, handler_code: str, suffix: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"sim2real-behav-fn-{suffix}-")
    zip_bytes = _zip_handler(handler_code)
    deadline = time.monotonic() + 60
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = e
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"function {name} never became creatable: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return name


def _wait_function_active(ctx: Any, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function {name} entered Failed state: {cfg}")
        time.sleep(2)
    raise AssertionError(f"function {name} did not become Active within {timeout_s}s")


def _invoke(ctx: Any, name: str, payload: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name,
        Payload=json.dumps(payload).encode("utf-8"),
        InvocationType="RequestResponse",
    )
    return json.loads(resp["Payload"].read())


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
