"""eventbridge-rule-target-sns-arn-publish."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-target-sns-arn-publish"
GROUP = "event-propagation"
SERVICES = ["events", "lambda", "sns"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """EventBridge rule with Targets[].Arn=<sns-topic> publishes the matched event to a topic
    whose policy allows events.amazonaws.com to publish."""
    topic_arn = _create_topic(ctx)
    queue_url = _create_queue_subscribed_to_topic(ctx, topic_arn)

    source = ctx.unique_name("sim2real.evtsns.src-")
    rule_name, rule_arn = _create_rule(ctx, source)
    _allow_events_to_publish(ctx, topic_arn, rule_arn)

    events = ctx.client("events")
    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": topic_arn}])
    ctx.on_cleanup(
        _tolerant(
            lambda: events.remove_targets(Rule=rule_name, Ids=["1"]),
            "ResourceNotFoundException",
        )
    )

    marker = ctx.unique_name("marker-")
    events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "sim2real.test",
                "Detail": json.dumps({"marker": marker}),
            }
        ]
    )

    messages = _wait_for_matching_message(ctx, queue_url, marker, timeout_s=90.0)
    assert len(messages) >= 1, "expected at least one SNS delivery for the matched event"
    envelope = messages[0]
    assert envelope["TopicArn"] == topic_arn, (
        f"expected SNS notification TopicArn {topic_arn!r}, got {envelope.get('TopicArn')!r}"
    )
    event_obj = json.loads(envelope["Message"])
    assert event_obj["detail"]["marker"] == marker, (
        f"expected delivered event detail.marker {marker!r}, got {event_obj.get('detail', {}).get('marker')!r}"
    )
    subs = [
        s["SubscriptionArn"]
        for s in _paged(ctx.client("sns"), "list_subscriptions_by_topic", "Subscriptions", TopicArn=topic_arn)
        if s.get("Protocol") == "sqs"
    ]
    assert len(subs) == 1, f"expected exactly 1 sqs subscription on the topic, got {len(subs)}"
    # Tear down in reverse dependency order and prove each resource gone.
    _gone_rule(ctx, rule_name, ["1"])
    _gone_subscription(ctx, subs[0], topic_arn)
    _gone_topic(ctx, topic_arn)
    _gone_queue(ctx, queue_url.rstrip("/").split("/")[-1], queue_url)


# ===== helpers =====


def _create_topic(ctx):
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-evtsns-topic-")
    arn = sns.create_topic(Name=name, Tags=[{"Key": "sim2real", "Value": "1"}])["TopicArn"]
    ctx.on_cleanup(_tolerant(lambda: sns.delete_topic(TopicArn=arn), "NotFound"))
    return arn


def _create_queue_subscribed_to_topic(ctx, topic_arn):
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    q_name = ctx.unique_name("sim2real-evtsns-queue-")
    url = sqs.create_queue(QueueName=q_name, tags={"sim2real": "1"})["QueueUrl"]
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=url), *_SQS_NF))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True
    )["SubscriptionArn"]
    ctx.on_cleanup(_tolerant(lambda: sns.unsubscribe(SubscriptionArn=sub_arn), "NotFound"))
    return url


def _allow_events_to_publish(ctx, topic_arn, rule_arn):
    sns = ctx.client("sns")
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    policy_doc = json.loads(attrs["Policy"])
    policy_doc["Statement"].append(
        {
            "Sid": "AllowEventBridgePublish",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "SNS:Publish",
            "Resource": topic_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }
    )
    sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(policy_doc)
    )


def _create_rule(ctx, source):
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-evtsns-rule-")
    pattern = json.dumps({"source": [source]})
    resp = events.put_rule(
        Name=rule_name,
        EventPattern=pattern,
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    rule_arn = resp["RuleArn"]

    def _cleanup():
        targets = events.list_targets_by_rule(Rule=rule_name).get("Targets", [])
        if targets:
            events.remove_targets(Rule=rule_name, Ids=[t["Id"] for t in targets])
        events.delete_rule(Name=rule_name)

    ctx.on_cleanup(_tolerant(_cleanup, "ResourceNotFoundException"))
    return rule_name, rule_arn


def _wait_for_matching_message(ctx, queue_url, marker, timeout_s=90.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    matched = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            try:
                envelope = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                envelope = {}
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in envelope.get("Message", ""):
                matched.append(envelope)
        if matched:
            return matched
    return matched


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, message: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status``, exactly the message ``message``."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == message, f"{what}: {code} message: expected {message!r}, got {msg!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, message, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, message)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _poll_absent(listing, what: str, timeout_s: float = _GONE_S) -> None:
    """Poll ``listing()`` until it is empty (bounded); fail with ``what`` and the last listing."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = listing()
        if not last:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} {timeout_s:.0f}s after the delete: {last!r}")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")
_SQS_GONE = "The specified queue does not exist."


def _gone_rule(ctx, name: str, target_ids: list[str], bus: str = "default") -> None:
    ev = ctx.client("events")
    if target_ids:
        ev.remove_targets(Rule=name, EventBusName=bus, Ids=target_ids)
    ev.delete_rule(Name=name, EventBusName=bus)
    nf = ("ResourceNotFoundException",)
    gone = f"Rule {name} does not exist on EventBus {bus}."
    _poll_refused(lambda: ev.describe_rule(Name=name, EventBusName=bus), nf, 400, f"DescribeRule {name}", gone)
    listed = {r["Name"] for r in ev.list_rules(NamePrefix=name, EventBusName=bus).get("Rules", [])}
    assert name not in listed, f"ListRules still lists deleted rule {name}"
    _refused(
        lambda: ev.put_targets(Rule=name, EventBusName=bus, Targets=[{"Id": "gone", "Arn": f"arn:aws:sqs:{ctx.region}:{ctx.account}:gone"}]),
        nf, 400, f"PutTargets {name}", gone,
    )


def _gone_subscription(ctx, sub_arn: str, topic_arn: str) -> None:
    sns = ctx.client("sns")
    sns.unsubscribe(SubscriptionArn=sub_arn)
    nf = ("NotFound",)
    _poll_refused(lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn), nf, 404, "GetSubscriptionAttributes", "Subscription does not exist")
    listed = {s["SubscriptionArn"] for s in _paged(sns, "list_subscriptions_by_topic", "Subscriptions", TopicArn=topic_arn)}
    assert sub_arn not in listed, "ListSubscriptionsByTopic still lists the removed subscription"
    _refused(
        lambda: sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="RawMessageDelivery", AttributeValue="true"),
        nf, 404, "SetSubscriptionAttributes on removed subscription", "Subscription does not exist",
    )


def _gone_topic(ctx, arn: str) -> None:
    sns = ctx.client("sns")
    sns.delete_topic(TopicArn=arn)
    nf = ("NotFound",)
    _poll_refused(lambda: sns.get_topic_attributes(TopicArn=arn), nf, 404, "GetTopicAttributes", "Topic does not exist")
    # The listing and the by-ARN read need not converge at the same instant: each is polled.
    _poll_absent(
        lambda: [t["TopicArn"] for t in _paged(sns, "list_topics", "Topics") if t["TopicArn"] == arn],
        "ListTopics still lists the deleted topic",
    )
    _poll_refused(lambda: sns.publish(TopicArn=arn, Message="gone"), nf, 404, "Publish to deleted topic", "Topic does not exist")


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # AWS documents up to 60 s for a deleted queue to stop answering.
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}", _SQS_GONE)
    # The listing and the URL need not converge at the same instant: each is polled.
    _poll_absent(
        lambda: [
            u
            for u in sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
            if u.rstrip("/").split("/")[-1] == name
        ],
        f"ListQueues still lists deleted queue {name}",
    )
    _poll_refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}", _SQS_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
