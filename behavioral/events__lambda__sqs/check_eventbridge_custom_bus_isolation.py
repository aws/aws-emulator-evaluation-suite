"""eventbridge-custom-bus-isolation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-custom-bus-isolation"
GROUP = "event-propagation"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule created on a custom event bus only reacts to PutEvents sent to that bus: the
    same matching payload sent to the default bus is not delivered, but sent to the custom
    bus (EventBusName=...) it is delivered to the target queue."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    bus_name = ctx.unique_name("sim2real-bus-")
    events.create_event_bus(Name=bus_name)["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    queue = _create_queue(ctx)

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {"source": ["sim2real.bustest"], "detail-type": ["BusEvent"]}
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), EventBusName=bus_name
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, EventBusName=bus_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})

    events.put_targets(
        Rule=rule_name, EventBusName=bus_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}]
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=["t1"]))

    detail = {"tag": "bus-event"}

    # Same matching payload sent to the DEFAULT bus must not reach the custom-bus rule. Confirm
    # PutEvents itself was accepted first -- otherwise a target that silently rejects the entry
    # would leave the queue empty for the wrong reason and this negative would be unprovable.
    default_resp = events.put_events(
        Entries=[
            {"Source": "sim2real.bustest", "DetailType": "BusEvent", "Detail": json.dumps(detail)}
        ]
    )
    assert default_resp["FailedEntryCount"] == 0, (
        f"PutEvents to the default bus was not accepted: {default_resp['Entries']}"
    )
    _assert_no_message(sqs, queue["url"], timeout_s=20.0)

    # Sent explicitly to the custom bus, it is delivered.
    custom_resp = events.put_events(
        Entries=[
            {
                "Source": "sim2real.bustest",
                "DetailType": "BusEvent",
                "Detail": json.dumps(detail),
                "EventBusName": bus_name,
            }
        ]
    )
    assert custom_resp["FailedEntryCount"] == 0, (
        f"PutEvents to the custom bus was not accepted: {custom_resp['Entries']}"
    )
    messages = _poll_until(
        lambda: _drain(sqs, queue["url"]),
        lambda msgs: len(msgs) >= 1,
        timeout_s=60.0,
        interval_s=2.0,
    )
    body = json.loads(messages[0]["Body"])
    assert body["detail"] == detail, f"expected delivered detail {detail!r}, got {body['detail']!r}"


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _drain(sqs, url, max_msgs=10, wait=2):
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=max_msgs, WaitTimeSeconds=wait)
    return resp.get("Messages", [])


def _assert_no_message(sqs, url, timeout_s=20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = _drain(sqs, url, wait=5)
        if msgs:
            raise AssertionError(f"unexpected cross-bus delivery: {msgs}")
        time.sleep(1)


def _create_queue(ctx, fifo=False, extra_attrs=None):
    sqs = ctx.client("sqs")
    suffix = ".fifo" if fifo else ""
    name = ctx.unique_name("sim2real-q-") + suffix
    attrs = dict(extra_attrs or {})
    if fifo:
        attrs["FifoQueue"] = "true"
        attrs.setdefault("ContentBasedDeduplication", "true")
    url = sqs.create_queue(QueueName=name, Attributes=attrs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
