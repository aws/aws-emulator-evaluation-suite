"""filter-policy-message-body-scope-numeric-exists-and-anything-but-decide-delivery."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-policy-message-body-scope-numeric-exists-and-anything-but-decide-delivery"
GROUP = "server-side"
SERVICES = ["sns"]

_SCENARIO = "sns-fp-body-scope-operators"


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Under FilterPolicyScope=MessageBody, numeric, `exists` and `anything-but` decide delivery on nested JSON: a
    body with `order.total` > 100, no `order.status` and `tag` not "blocked" is delivered, one breaking any of
    the three is withheld; an unfiltered twin subscriber receives every body and bounds the wait."""
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    twin_url, twin_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, twin_arn, attributes={"RawMessageDelivery": "true"})

    policy = {
        "order": {"total": [{"numeric": [">", 100]}], "status": [{"exists": False}]},
        "tag": [{"anything-but": "blocked"}],
    }
    url, arn = _create_queue_for_topic(ctx, topic_arn)
    sub = _subscribe_and_confirm(
        ctx, topic_arn, arn,
        attributes={"RawMessageDelivery": "true", "FilterPolicyScope": "MessageBody",
                    "FilterPolicy": json.dumps(policy)})
    stored = json.loads(sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]["FilterPolicy"])
    assert stored == policy, f"the stored FilterPolicy must round-trip verbatim, got {stored!r}"

    marker = ctx.unique_name("sim2real-behav-sns-fpbody-op-")
    bodies = {
        "match": {"id": marker, "which": "match", "order": {"total": 150}, "tag": "ok"},
        "fail_numeric": {"id": marker, "which": "fail_numeric", "order": {"total": 50}, "tag": "ok"},
        "fail_exists": {"id": marker, "which": "fail_exists",
                        "order": {"total": 150, "status": "shipped"}, "tag": "ok"},
        "fail_anything_but": {"id": marker, "which": "fail_anything_but",
                              "order": {"total": 150}, "tag": "blocked"},
    }
    for body in bodies.values():
        sns.publish(TopicArn=topic_arn, Message=json.dumps(body))

    twin_seen = _receive_keyed(
        ctx, twin_url, lambda m: json.loads(m["Body"])["which"], set(bodies),
        timeout_s=90.0, description="the unfiltered twin receives every body")
    assert {json.loads(m["Body"])["id"] for m in twin_seen.values()} == {marker}, (
        "the twin's bodies must all carry this run's marker")

    filtered_seen = _receive_keyed(
        ctx, url, lambda m: json.loads(m["Body"])["which"], {"match"}, timeout_s=60.0,
        description="the filtered subscription receives the one body satisfying all three operators")
    assert json.loads(filtered_seen["match"]["Body"]) == bodies["match"], (
        "the admitted body must be delivered unchanged")

    leaked = _drain(ctx, url, window_s=15.0)
    assert leaked == [], (
        f"a body failing the numeric, exists or anything-but operator must be withheld; "
        f"leaked {leaked!r}")


def _create_topic(ctx) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    arn = sns.create_topic(Name=name, Tags=[{"Key": "sim2real", "Value": _SCENARIO}])["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn

def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic send to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": _SCENARIO})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: _delete_queue_if_present(ctx, u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn

def _delete_queue_if_present(ctx, url: str) -> None:
    """DeleteQueue; a queue the check itself already deleted is the one tolerated outcome."""
    try:
        ctx.client("sqs").delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
            raise

def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, *, attributes: dict,
                           timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
                            ReturnSubscriptionArn=True, Attributes=attributes)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: ctx.client("sns").unsubscribe(SubscriptionArn=s))
    _poll_until(
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation"),
        lambda pending: pending == "false",
        timeout_s=timeout_s, interval_s=1.0,
        description="the sqs subscription leaves PendingConfirmation",
    )
    return sub_arn

def _poll_until(fn, pred, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry; RAISES on the deadline so a timeout can never read as a pass."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not satisfied within {timeout_s}s, last value {value!r}")
        time.sleep(interval_s)
        value = fn()
    return value

def _receive_keyed(ctx, queue_url: str, key, wanted: set[str], *, timeout_s: float,
                   description: str) -> dict[str, dict]:
    """Long-poll until a message keyed `key(msg)` exists for every wanted key; RAISES on the
    deadline. Each message is returned whole."""
    sqs = ctx.client("sqs")
    got: dict[str, dict] = {}
    other: list[str] = []
    deadline = time.monotonic() + timeout_s
    while not wanted <= set(got):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                k = key(msg)
            except (ValueError, KeyError):
                other.append(msg["Body"][:160])
                continue
            if k in wanted and k not in got:
                got[k] = msg
            else:
                other.append(msg["Body"][:160])
        if not wanted <= set(got) and time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: {sorted(wanted - set(got))!r} never arrived within "
                f"{timeout_s}s; other bodies seen: {other!r}")
    return got

def _drain(ctx, queue_url: str, *, window_s: float) -> list[str]:
    """Long-poll for the whole window and return EVERY body seen, so the caller can assert on
    leakage rather than discard it."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg["Body"][:300])
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
