"""sns-notification-config-lambda-destination-update."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sns-notification-config-lambda-destination-update"
GROUP = "notification-config"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Redirecting an SNS subscription's Lambda destination sends subsequent notifications
    only to the new function, not the old one."""
    role_arn = _create_lambda_role(ctx)
    sink = _create_queue(ctx, "sink")
    fn_a = _create_forwarder_function(
        ctx, role_arn, sink_queue_url=sink["url"], extra_env={"MARK": "fn-a"}
    )
    fn_b = _create_forwarder_function(
        ctx, role_arn, sink_queue_url=sink["url"], extra_env={"MARK": "fn-b"}
    )
    topic_arn = _create_topic(ctx)

    _allow_sns_invoke(ctx, fn_a["name"], topic_arn)
    sns = ctx.client("sns")
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="lambda", Endpoint=fn_a["arn"]
    )["SubscriptionArn"]

    sns.publish(TopicArn=topic_arn, Message="msg-for-fn-a")

    collected: list[dict[str, Any]] = []

    def probe_a():
        collected.extend(_drain_sink(ctx, sink["url"], wait_s=3))
        return [m for m in collected if m.get("mark") == "fn-a"]

    delivered_a = _wait_for_effect(
        probe_a,
        lambda ms: len(ms) >= 1,
        timeout_s=90,
        interval_s=3.0,
        description="notification delivered to fn-a",
    )
    assert len(delivered_a) == 1

    # "Update" the destination: SNS subscriptions cannot mutate Endpoint in place, so the
    # redirection is realized by replacing the subscription (the standard way to change an
    # SNS->Lambda destination).
    sns.unsubscribe(SubscriptionArn=sub_arn)
    listed = _await_subscription_gone(ctx, topic_arn, sub_arn)
    assert sub_arn not in [s["SubscriptionArn"] for s in listed], (
        f"the unsubscribed destination is still listed: {[s['SubscriptionArn'] for s in listed]!r}"
    )
    code, message = _client_error(lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn))
    assert code == "NotFound", (
        f"GetSubscriptionAttributes on the redirected-away subscription was not rejected: {code!r}"
    )
    assert message == "Subscription does not exist", f"got message {message!r}"
    _allow_sns_invoke(ctx, fn_b["name"], topic_arn)
    new_sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="lambda", Endpoint=fn_b["arn"]
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=new_sub_arn))

    sns.publish(TopicArn=topic_arn, Message="msg-for-fn-b")

    def probe_b():
        collected.extend(_drain_sink(ctx, sink["url"], wait_s=3))
        return [m for m in collected if m.get("mark") == "fn-b"]

    delivered_b = _wait_for_effect(
        probe_b,
        lambda ms: len(ms) >= 1,
        timeout_s=90,
        interval_s=3.0,
        description="notification delivered to fn-b after redirection",
    )
    assert len(delivered_b) == 1
    # fn-a must not have received the second notification: redirection is exclusive.
    still_only_one_a = [m for m in collected if m.get("mark") == "fn-a"]
    assert len(still_only_one_a) == 1, (
        f"old destination fn-a received traffic after redirection: {still_only_one_a}"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


_FORWARDER_CODE = """
import json
import os
import boto3

_sqs = boto3.client("sqs")
SINK_QUEUE_URL = os.environ.get("SINK_QUEUE_URL")
MARK = os.environ.get("MARK", "")


def handler(event, context):
    records = event.get("Records", [])
    if records and "Sns" in records[0]:
        message = records[0]["Sns"]["Message"]
        payload = {"kind": "sns", "mark": MARK, "message": message}
    elif records:
        bodies = [r.get("body") for r in records]
        payload = {"kind": "sqs-batch", "mark": MARK, "record_count": len(records), "bodies": bodies}
    else:
        payload = {"kind": "other", "mark": MARK, "event": event}
    if SINK_QUEUE_URL:
        _sqs.send_message(QueueUrl=SINK_QUEUE_URL, MessageBody=json.dumps(payload))
    return {"ok": True}
"""


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-b5-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    )
    policy_name = ctx.unique_name("sim2real-b5-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["sqs:*"], "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _create_forwarder_function(ctx, role_arn, sink_queue_url=None, extra_env=None) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-b5-fn-")
    env_vars: dict[str, str] = {}
    if sink_queue_url:
        env_vars["SINK_QUEUE_URL"] = sink_queue_url
    if extra_env:
        env_vars.update(extra_env)
    zip_bytes = _zip_bytes(_FORWARDER_CODE)
    resp = None
    last_err = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": env_vars} if env_vars else {},
            )
            break
        except botocore.exceptions.ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s in ("Active", "Failed"),
        timeout_s=90,
        interval_s=3.0,
        description=f"function {name} Active",
    )
    return {"name": name, "arn": arn}


def _create_queue(ctx, prefix="q") -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-b5-{prefix}-"))[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return {"url": url, "arn": arn}


def _drain_sink(ctx, sink_url, wait_s=2) -> list:
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(
        QueueUrl=sink_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s
    )
    for m in resp.get("Messages", []):
        out.append(json.loads(m["Body"]))
        sqs.delete_message(QueueUrl=sink_url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-b5-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _client_error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises. Raises if fn SUCCEEDS -- an unexpected
    success is the strongest possible signal."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {result!r}"
    )


def _await_subscription_gone(ctx, topic_arn, sub_arn, timeout_s=60.0) -> list:
    """Poll ListSubscriptionsByTopic until sub_arn is absent; returns the final listing."""
    sns = ctx.client("sns")
    deadline = time.monotonic() + timeout_s
    listed: list = []
    while time.monotonic() < deadline:
        listed = sns.list_subscriptions_by_topic(TopicArn=topic_arn).get("Subscriptions", [])
        if sub_arn not in [s["SubscriptionArn"] for s in listed]:
            return listed
        time.sleep(1.0)
    raise AssertionError(
        f"{sub_arn!r} was still listed on {topic_arn!r} {timeout_s}s after Unsubscribe: "
        f"{[s['SubscriptionArn'] for s in listed]!r}"
    )


def _allow_sns_invoke(ctx, function_name, topic_arn) -> None:
    lam = ctx.client("lambda")
    statement_id = ctx.unique_name("sim2real-b5-perm-")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com",
        SourceArn=topic_arn,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(
            FunctionName=function_name, StatementId=statement_id
        )
    )


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
