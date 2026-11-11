"""sns-lambda-notification-message-attributes-filter."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sns-lambda-notification-message-attributes-filter"
GROUP = "notification"
SERVICES = ["lambda", "sns", "sqs"]

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": "sim2real-xsvc"}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


_HANDLER_SRC = """
import json
import os
import boto3

def handler(event, context):
    sqs = boto3.client("sqs")
    queue_url = os.environ["RELAY_QUEUE_URL"]
    for record in event.get("Records", []):
        sns = record.get("Sns") or {}
        body = sns.get("Message", json.dumps(record))
        sqs.send_message(QueueUrl=queue_url, MessageBody=body)
    return {"processed": len(event.get("Records", []))}
"""


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FilterPolicy on an SNS->Lambda subscription suppresses invocation for non-matching
    message attributes and allows invocation through for matching ones."""
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    sns = ctx.client("sns")

    relay_url = _create_queue(ctx)
    relay_arn = sqs.get_queue_attributes(QueueUrl=relay_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_arn = _create_lambda_role(ctx, relay_arn)
    fn_name, fn_arn = _create_relay_function(ctx, role_arn, relay_url)

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-topic-"), Tags=_xsvc_tags_kv()
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    lam.add_permission(
        FunctionName=fn_name,
        StatementId="AllowSNSInvoke",
        Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com",
        SourceArn=topic_arn,
    )

    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="lambda", Endpoint=fn_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn,
        AttributeName="FilterPolicy",
        AttributeValue=json.dumps({"event_type": ["important"]}),
    )

    # Non-matching publish: must NOT reach the relay queue via Lambda invocation.
    sns.publish(
        TopicArn=topic_arn,
        Message="should-be-filtered",
        MessageAttributes={"event_type": {"DataType": "String", "StringValue": "trivial"}},
    )
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=relay_url, MaxNumberOfMessages=10, WaitTimeSeconds=3)
        for msg in resp.get("Messages", []):
            raise AssertionError(f"non-matching message reached Lambda relay: {msg['Body']!r}")

    # Matching publish: must reach the relay queue.
    sns.publish(
        TopicArn=topic_arn,
        Message="should-pass-filter",
        MessageAttributes={"event_type": {"DataType": "String", "StringValue": "important"}},
    )
    matched = _poll_for_message(ctx, relay_url, timeout_s=60.0)
    assert matched == "should-pass-filter", f"unexpected relayed body: {matched!r}"


def _create_queue(ctx) -> str:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-relay-"), tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return url


def _create_lambda_role(ctx, relay_queue_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="relay-sqs-send",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": relay_queue_arn}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="relay-sqs-send"))
    return role_arn


def _zip_bytes(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_relay_function(ctx, role_arn: str, relay_queue_url: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-xsvc-fn-")
    last_err: Exception | None = None
    for _ in range(10):
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _zip_bytes(_HANDLER_SRC)},
                Timeout=30,
                Environment={"Variables": {"RELAY_QUEUE_URL": relay_queue_url}},
                Tags=_xsvc_resource_tags(),
            )
            break
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] in ("InvalidParameterValueException",):
                time.sleep(2)
                continue
            raise
    else:
        raise AssertionError(f"could not create function after retries: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    waiter = lam.get_waiter("function_active_v2")
    waiter.wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name, resp["FunctionArn"]


def _poll_for_message(ctx, queue_url: str, timeout_s: float) -> Any:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg["Body"]
    raise AssertionError(f"no message relayed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
