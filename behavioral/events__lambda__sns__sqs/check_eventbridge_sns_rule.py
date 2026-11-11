"""eventbridge-sns-rule."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-sns-rule"

GROUP = "event-propagation"

SERVICES = ["events", "lambda", "sns", "sqs"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """EventBridge publishes matching events to the SNS target, observed via an SQS subscriber."""
    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    events = ctx.client("events")

    sqs_policy = {
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
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(sqs_policy)}
    )
    sub = sns.subscribe(TopicArn=topic["arn"], Protocol="sqs", Endpoint=queue["arn"])
    ctx.on_cleanup(
        lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub["SubscriptionArn"])
    )

    topic_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sns:Publish",
                "Resource": topic["arn"],
            }
        ],
    }
    sns.set_topic_attributes(
        TopicArn=topic["arn"],
        AttributeName="Policy",
        AttributeValue=json.dumps(topic_policy),
    )

    rule_name = ctx.unique_name("rule-sns-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {"source": ["test.sns"], "detail-type": ["AlertRaised"]}
        ),
    )
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": topic["arn"]}])
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["t1"])
    )

    match_entry = {
        "Source": "test.sns",
        "DetailType": "AlertRaised",
        "Detail": json.dumps({"id": "eb-sns-1"}),
    }

    collected: list[dict] = []

    # Rule activation is eventually consistent — re-publish on every poll so the
    # EventBridge -> SNS -> SQS hop is not raced by rule propagation.
    def probe():
        events.put_events(Entries=[match_entry])
        resp = sqs.receive_message(
            QueueUrl=queue["url"], MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for m in resp.get("Messages", []):
            collected.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue["url"], ReceiptHandle=m["ReceiptHandle"])
        return collected

    _wait_for_effect(probe, lambda c: len(c) > 0, timeout_s=90, interval_s=5.0)
    assert collected, "EventBridge event never reached the SNS target"

    # The SNS envelope wraps the EventBridge event; the detail must survive both hops.
    envelope = collected[0]
    detail = json.loads(envelope["Message"])["detail"]
    assert detail["id"] == "eb-sns-1", (
        f"expected detail.id 'eb-sns-1' to survive the EventBridge->SNS->SQS hop, got {detail!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


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


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"name": name, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
