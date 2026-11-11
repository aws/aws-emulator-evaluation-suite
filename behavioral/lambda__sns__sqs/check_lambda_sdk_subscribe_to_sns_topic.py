"""lambda-sdk-subscribe-to-sns-topic."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-sdk-subscribe-to-sns-topic"
GROUP = "sdk-call"
SERVICES = ["lambda", "sns", "sqs"]

_CODE_SUBSCRIBE = """
import boto3

def handler(event, context):
    sns = boto3.client("sns")
    try:
        resp = sns.subscribe(
            TopicArn=event["topic_arn"],
            Protocol="sqs",
            Endpoint=event["queue_arn"],
            ReturnSubscriptionArn=True,
        )
        return {"ok": True, "subscription_arn": resp["SubscriptionArn"]}
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
        return {"ok": False, "error_code": code}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function calls sns.subscribe to wire an SQS endpoint to a topic; the resulting
    subscription is real (confirmed) and end-to-end delivery through it actually works."""
    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    # allow SNS to deliver into the queue so we can prove end-to-end delivery, not just the API call
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": topic["arn"]}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})

    role_arn = _create_role(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sns:Subscribe", "Resource": topic["arn"]}],
        },
    )
    fn = _create_function(ctx, role_arn, _CODE_SUBSCRIBE)
    result = _invoke(ctx, fn, {"topic_arn": topic["arn"], "queue_arn": queue["arn"]})
    assert result["ok"] is True, result
    sub_arn = result["subscription_arn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    # the subscription must be real and confirmed (SQS endpoints auto-confirm without extra action)
    subs = sns.list_subscriptions_by_topic(TopicArn=topic["arn"])["Subscriptions"]
    matching = [s for s in subs if s["SubscriptionArn"] == sub_arn]
    assert len(matching) == 1, subs
    assert matching[0]["Endpoint"] == queue["arn"], (
        f"expected subscription endpoint {queue['arn']}, got {matching[0]['Endpoint']}"
    )

    # end-to-end: a publish now actually reaches the queue through the subscription the lambda created
    marker = ctx.unique_name("published-")
    sns.publish(TopicArn=topic["arn"], Message=marker)
    delivered = _poll_for_message(ctx, queue["url"], marker, timeout_s=60)
    assert delivered, "SNS publish never reached the queue via the lambda-created subscription"


_PREFIX = "sim2real-snssqslambda-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(ctx: Any, inline_policy: dict | None) -> str:
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv()
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_policy is not None:
        iam.put_role_policy(RoleName=role_name, PolicyName="perm", PolicyDocument=json.dumps(inline_policy))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="perm"))
    return role_arn


def _wait_active(ctx: Any, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _create_function(ctx: Any, role_arn: str, code: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    zip_bytes = _lambda_zip(code)
    deadline = time.monotonic() + 90.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Publish=True,
                Tags=_resource_tags(),
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    else:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    # create_function auto-creates /aws/lambda/<name> on first invoke; it survives function
    # deletion and is not swept by name-prefix, so it must be cleaned up explicitly.
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"))
    _wait_active(ctx, name)
    return name


def _invoke(ctx: Any, name: str, payload: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name,
        Payload=json.dumps(payload).encode("utf-8"),
        InvocationType="RequestResponse",
    )
    body = json.loads(resp["Payload"].read())
    assert "FunctionError" not in resp, f"unexpected FunctionError: {resp.get('FunctionError')}, body={body}"
    return body


def _create_queue(ctx: Any, attrs: dict | None = None) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=_xname(ctx, "q"), Attributes=attrs or {}, tags=_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_topic(ctx: Any) -> dict[str, str]:
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=_xname(ctx, "topic"), Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"arn": arn}


def _poll_for_message(ctx: Any, queue_url: str, marker: str, timeout_s: float = 60.0) -> bool:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            try:
                envelope = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                envelope = {}
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if envelope.get("Message") == marker:
                return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
