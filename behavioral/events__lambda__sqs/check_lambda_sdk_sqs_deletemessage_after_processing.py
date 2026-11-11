"""lambda-sdk-sqs-deletemessage-after-processing."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-sqs-deletemessage-after-processing"
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
    client.delete_message(QueueUrl=event['queue_url'], ReceiptHandle=msgs[0]['ReceiptHandle'])
    return {'ok': True, 'body': msgs[0]['Body']}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda explicitly deleting a message removes it from the queue, preventing redelivery."""
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-q-"),
        Attributes={"VisibilityTimeout": "3"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))

    role_arn = _create_role(
        ctx,
        [
            {"Effect": "Allow", "Action": "sqs:ReceiveMessage", "Resource": "*"},
            {"Effect": "Allow", "Action": "sqs:DeleteMessage", "Resource": "*"},
        ],
        "delete-msg",
    )
    fn_name = _create_function(ctx, role_arn, _HANDLER, "delete-msg")

    body_text = "sim2real-delete-after-processing"
    sqs.send_message(QueueUrl=queue_url, MessageBody=body_text)

    result = _poll_until(
        lambda: _invoke(ctx, fn_name, {"queue_url": queue_url}),
        lambda b: b.get("ok") is True,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert result["body"] == body_text, f"expected delivered body {body_text!r}, got {result['body']!r}"

    # Positive control, on the same queue, before trusting the absence check below: a
    # message that is received but never deleted must still redeliver once its
    # visibility timeout elapses. Without this, a target with no redelivery path at
    # all (e.g. one that treats ReceiveMessage as an implicit delete) would pass the
    # "deleted message never comes back" assertion for free.
    control_body = "sim2real-control-not-deleted"
    sqs.send_message(QueueUrl=queue_url, MessageBody=control_body)
    _poll_until(
        lambda: sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get(
            "Messages", []
        ),
        lambda msgs: any(m["Body"] == control_body for m in msgs),
        timeout_s=20.0,
    )
    reappeared = _poll_until(
        lambda: sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=3).get(
            "Messages", []
        ),
        lambda msgs: any(m["Body"] == control_body for m in msgs),
        timeout_s=12.0,
    )
    control_msg = next(m for m in reappeared if m["Body"] == control_body)
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=control_msg["ReceiptHandle"])

    # Bounded poll past several multiples of the (short) visibility timeout: a deleted
    # message must never reappear, unlike the merely-received-but-not-deleted control above.
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        assert resp.get("Messages", []) == [], "deleted message was redelivered"
        time.sleep(1)

    attrs = _wait_counters_zero(
        ctx, sqs, queue_url,
        ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"expected 0 visible messages after delete, got {attrs['ApproximateNumberOfMessages']}"
    )
    assert attrs["ApproximateNumberOfMessagesNotVisible"] == "0", (
        f"expected 0 in-flight messages after delete, got {attrs['ApproximateNumberOfMessagesNotVisible']}"
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


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_counters_zero(ctx, sqs, queue_url, names, *, cap_s=90.0, interval_s=3.0):
    """Read the queue's *names* counters until each is "0" or cap_s ends; return the last read.

    SQS documents these counters as eventually consistent: they "may not achieve consistency until
    at least 1 minute after the producers stop sending messages" (GetQueueAttributes).
    """
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    stop = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=list(names))["Attributes"]
        if all(attrs.get(n) == "0" for n in names):
            return attrs
        if time.monotonic() >= stop:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s counter wait ended (last={attrs!r}); not graded"
                )
            return attrs
        time.sleep(interval_s)


def _create_role(ctx: Any, statements: list, suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-behav-role-{suffix}-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags={"sim2real": CHECK},
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
