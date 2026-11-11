"""eventbridge-rule-event-pattern-content-filtering-sqs."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-rule-event-pattern-content-filtering-sqs"
GROUP = "event-propagation"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """EventBridge content-based pattern filtering (matching on a nested detail field) delivers
    only events whose detail satisfies the pattern into the SQS target queue; a non-matching
    event on the same source/detail-type is silently dropped by the rule."""
    queue = _create_queue_with_events_policy(ctx)

    rule = _put_rule(
        ctx,
        pattern={
            "source": ["sim2real.inventory"],
            "detail-type": ["StockLevelChanged"],
            "detail": {"status": ["critical"]},
        },
    )
    _put_targets(ctx, rule["name"], [{"Id": "sqs-target", "Arn": queue["arn"]}])

    events = ctx.client("events")
    # Non-matching event: same source/detail-type, but status != "critical".
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.inventory",
                "DetailType": "StockLevelChanged",
                "Detail": json.dumps({"sku": "SKU-A", "status": "normal"}),
            }
        ]
    )
    # Matching event.
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.inventory",
                "DetailType": "StockLevelChanged",
                "Detail": json.dumps({"sku": "SKU-B", "status": "critical"}),
            }
        ]
    )

    messages = _collect_messages(ctx, queue["url"], observe_s=45.0)
    assert len(messages) == 1, f"expected exactly 1 matching delivery, got {len(messages)}"
    body = json.loads(messages[0]["Body"])
    assert body["detail"]["sku"] == "SKU-B", f"expected delivered detail.sku 'SKU-B', got {body['detail'].get('sku')!r}"
    assert body["detail"]["status"] == "critical", (
        f"expected delivered detail.status 'critical', got {body['detail'].get('status')!r}"
    )


_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": "sim2real-ebl"}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _create_queue_with_events_policy(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-ebl-q-")
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    account_id = arn.split(":")[4]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {
                    "ArnEquals": {
                        "aws:SourceArn": f"arn:aws:events:{ctx.region}:{account_id}:rule/*"
                    }
                },
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return {"url": url, "arn": arn}


def _drain_queue(ctx, queue_url, max_messages=10, wait_s=2):
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=wait_s
    )
    for msg in resp.get("Messages", []):
        out.append(msg)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _collect_messages(ctx, queue_url, observe_s=45.0):
    """Drain the queue for a bounded observation window and return everything seen (used when
    we expect a SPECIFIC small count, not a lower bound)."""
    deadline = time.monotonic() + observe_s
    out = []
    while time.monotonic() < deadline:
        out.extend(_drain_queue(ctx, queue_url, wait_s=5))
    return out


def _put_rule(ctx, pattern=None, schedule=None, state="ENABLED", event_bus_name=None):
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-ebl-rule-")
    kwargs: dict[str, Any] = {"Name": name, "State": state, "Tags": _xsvc_tags_kv()}
    if pattern is not None:
        kwargs["EventPattern"] = json.dumps(pattern)
    if schedule is not None:
        kwargs["ScheduleExpression"] = schedule
    if event_bus_name:
        kwargs["EventBusName"] = event_bus_name
    resp = events.put_rule(**kwargs)
    if event_bus_name:
        ctx.on_cleanup(lambda: events.delete_rule(Name=name, EventBusName=event_bus_name))
    else:
        ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return {"name": name, "arn": resp["RuleArn"]}


def _put_targets(ctx, rule_name, targets, event_bus_name=None):
    events = ctx.client("events")
    kwargs: dict[str, Any] = {"Rule": rule_name, "Targets": targets}
    if event_bus_name:
        kwargs["EventBusName"] = event_bus_name
    resp = events.put_targets(**kwargs)
    if resp.get("FailedEntryCount", 0):
        raise AssertionError(f"put_targets failures: {resp['FailedEntries']}")
    ids = [t["Id"] for t in targets]

    def _cleanup():
        kw: dict[str, Any] = {"Rule": rule_name, "Ids": ids}
        if event_bus_name:
            kw["EventBusName"] = event_bus_name
        events.remove_targets(**kw)

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
