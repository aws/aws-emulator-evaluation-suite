"""lambda-sdk-sqs-changemessagevisibility-extends-lock."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-sqs-changemessagevisibility-extends-lock"
GROUP = "sdk-call"
SERVICES = ["events", "lambda", "sqs"]

_HANDLER = """
import boto3

def handler(event, context):
    client = boto3.client('sqs')
    resp = client.receive_message(
        QueueUrl=event['queue_url'], MaxNumberOfMessages=1, WaitTimeSeconds=5,
    )
    msgs = resp.get('Messages', [])
    if not msgs:
        return {'ok': False, 'reason': 'no-message'}
    client.change_message_visibility(
        QueueUrl=event['queue_url'],
        ReceiptHandle=msgs[0]['ReceiptHandle'],
        VisibilityTimeout=event['extend_to'],
    )
    return {'ok': True, 'body': msgs[0]['Body']}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda calling ChangeMessageVisibility extends the visibility timeout on the source queue."""
    sqs = ctx.client("sqs")
    # Short default visibility timeout so we can observe both "still locked past the
    # original window" and "eventually redelivered once the extension itself expires".
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-q-"),
        Attributes={"VisibilityTimeout": "6"},
        tags=_xsvc_resource_tags(),
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))

    role_arn = _create_role(
        ctx,
        [
            {"Effect": "Allow", "Action": "sqs:ReceiveMessage", "Resource": "*"},
            {"Effect": "Allow", "Action": "sqs:ChangeMessageVisibility", "Resource": "*"},
        ],
        "vis-extend",
    )
    fn_name = _create_function(ctx, role_arn, _HANDLER, "vis-extend")

    body_text = "sim2real-vis-extend-body"
    sqs.send_message(QueueUrl=queue_url, MessageBody=body_text)
    send_time = time.monotonic()

    result = _poll_until(
        lambda: _invoke(ctx, fn_name, {"queue_url": queue_url, "extend_to": 24}),
        lambda b: b.get("ok") is True,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert result["body"] == body_text, f"expected the lambda to echo body {body_text!r}, got {result!r}"

    # Past the *original* 6s window the message must still be invisible: the extension
    # (to 24s from receipt) must have taken effect, otherwise SQS would have redelivered it.
    while time.monotonic() - send_time < 9.0:
        time.sleep(0.5)
    still_hidden = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=1
    )
    assert still_hidden.get("Messages", []) == [], (
        f"expected no visible messages 9s after send (past the original 6s timeout), "
        f"got {still_hidden.get('Messages')!r} — the extension did not take effect"
    )

    # Once the *extended* window elapses, the message becomes visible again for redelivery.
    redelivered = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda msgs: len(msgs) == 1,
        timeout_s=40.0,
        interval_s=2.0,
    )
    assert redelivered[0]["Body"] == body_text, (
        f"expected the redelivered message body to be {body_text!r}, got {redelivered[0]!r}"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=redelivered[0]["ReceiptHandle"])

    # Free negative: the delete already happened above but was unasserted. Confirm it took
    # effect via an independent read — the queue must now be empty.
    after_delete = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
    assert after_delete.get("Messages", []) == [], (
        f"expected the queue to be empty after delete_message, got {after_delete.get('Messages')!r}"
    )


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_LOGS_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": "sim2real-behav-"}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=_xsvc_tags_kv(),
    )
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
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags=_xsvc_resource_tags(),
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
    # create_function auto-creates /aws/lambda/<name> on first invoke; that log group
    # survives function deletion, so it leaks unless removed explicitly here.
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    )
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
