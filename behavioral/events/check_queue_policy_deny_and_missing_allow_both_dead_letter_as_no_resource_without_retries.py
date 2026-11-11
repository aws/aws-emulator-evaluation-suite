"""queue-policy-deny-and-missing-allow-both-dead-letter-as-no-resource-without-retries."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "queue-policy-deny-and-missing-allow-both-dead-letter-as-no-resource-without-retries"
GROUP = "delivery-failure"
SERVICES = ["events"]

_RETRY = {"MaximumRetryAttempts": 185, "MaximumEventAgeInSeconds": 86400}
_DEAD_LETTER_KEYS = ["ERROR_CODE", "ERROR_MESSAGE", "RULE_ARN", "TARGET_ARN"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A queue whose policy denies events.amazonaws.com and a queue with no policy are both dead-lettered once,
    without retries, as NO_RESOURCE with SQS's NonExistentQueue message and the rule's ARN, while a healthy
    sibling receives the event; replacing the Deny with an Allow lets the next event land."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    bus = ctx.unique_name("sim2real-evb-dlq-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    source = ctx.unique_name("sim2real.deny.")
    rule = ctx.unique_name("sim2real-evb-denyrule-")
    rule_arn = events.put_rule(Name=rule, EventBusName=bus,
                               EventPattern=json.dumps({"source": [source]}))["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))

    denied_url, denied_arn = _queue(ctx, sqs, "deny")
    bare_url, bare_arn = _queue(ctx, sqs, "bare")
    healthy_url, healthy_arn = _queue(ctx, sqs, "ok")
    dlq_url, dlq_arn = _queue(ctx, sqs, "dlq")
    _set_policy(sqs, denied_url, denied_arn, rule_arn, "Deny")
    _set_policy(sqs, healthy_url, healthy_arn, rule_arn, "Allow")
    _set_policy(sqs, dlq_url, dlq_arn, rule_arn, "Allow")

    ids = ["denied", "bare", "healthy"]
    resp = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": "denied", "Arn": denied_arn, "RetryPolicy": _RETRY, "DeadLetterConfig": {"Arn": dlq_arn}},
        {"Id": "bare", "Arn": bare_arn, "RetryPolicy": _RETRY, "DeadLetterConfig": {"Arn": dlq_arn}},
        {"Id": "healthy", "Arn": healthy_arn},
    ])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=ids))
    assert resp["FailedEntryCount"] == 0, f"PutTargets reported {resp['FailedEntries']!r}"

    event_id = _put(events, bus, source, ctx.unique_name("m-"))
    healthy, _ = _await(sqs, healthy_url, lambda b, a: b.get("id") == event_id, 90.0)

    records: dict = {}
    deadline = time.monotonic() + 150.0
    while len(records) < 2 and time.monotonic() < deadline:
        for body, attrs in _receive(sqs, dlq_url):
            if body.get("id") == event_id:
                records[attrs.get("TARGET_ARN")] = (body, attrs)
    assert set(records) == {denied_arn, bare_arn}, (
        f"dead-letter records arrived for {len(records)} target(s), expected the denying and the bare queue"
    )

    body, attrs = records[denied_arn]
    assert sorted(attrs) == _DEAD_LETTER_KEYS, f"the denied target's dead-letter attributes were {sorted(attrs)!r}"
    assert attrs["ERROR_CODE"] == "NO_RESOURCE", f"an explicit queue-policy Deny dead-lettered as {attrs['ERROR_CODE']!r}"
    assert _shaped(attrs["ERROR_MESSAGE"]) == _NON_EXISTENT_QUEUE, (
        f"the denied target's ERROR_MESSAGE was {_shaped(attrs['ERROR_MESSAGE'])!r}"
    )
    assert attrs["RULE_ARN"] == rule_arn, "the denied target's dead-letter RULE_ARN does not name the rule"
    assert body == healthy, "the denied target's dead-lettered body differs from the delivered event"

    body, attrs = records[bare_arn]
    assert sorted(attrs) == _DEAD_LETTER_KEYS, f"the bare target's dead-letter attributes were {sorted(attrs)!r}"
    assert attrs["ERROR_CODE"] == "NO_RESOURCE", f"a queue with no policy dead-lettered as {attrs['ERROR_CODE']!r}"
    assert _shaped(attrs["ERROR_MESSAGE"]) == _NON_EXISTENT_QUEUE, (
        f"the bare target's ERROR_MESSAGE was {_shaped(attrs['ERROR_MESSAGE'])!r}"
    )
    assert attrs["RULE_ARN"] == rule_arn, "the bare target's dead-letter RULE_ARN does not name the rule"
    assert body == healthy, "the bare target's dead-lettered body differs from the delivered event"

    for label, url in (("denying", denied_url), ("bare", bare_url)):
        left = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
        assert left == [], f"the {label} queue holds {len(left)} message(s)"

    # Restore: the one broken thing is repaired, and the same target now receives.
    _set_policy(sqs, denied_url, denied_arn, rule_arn, "Allow")
    got = _resend_until(events, sqs, bus, source, ctx.unique_name("m2-"), denied_url, timeout_s=120.0)
    assert got["source"] == source, f"event delivered after the repair had source {got['source']!r}"


# SQS's own errors as EventBridge records them; the minted request id is shaped.
_NON_EXISTENT_QUEUE = (
    "The specified queue does not exist or you do not have access to it. (Service: AmazonSQS; "
    "Status Code: 400; Error Code: AWS.SimpleQueueService.NonExistentQueue; Request ID: <id>; Proxy: null)"
)


def _shaped(message: str) -> str:
    return re.sub(r"Request ID: [^;]+;", "Request ID: <id>;", message or "")


def _queue(ctx, sqs, label: str) -> tuple[str, str]:
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-evb-{label}-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _set_policy(sqs, url: str, arn: str, rule_arn: str, effect: str) -> None:
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": effect, "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})


def _put(events, bus: str, source: str, marker: str) -> str:
    resp = events.put_events(Entries=[{"EventBusName": bus, "Source": source, "DetailType": "sim2real-dlq",
                                       "Detail": json.dumps({"marker": marker})}])
    assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
    return resp["Entries"][0]["EventId"]


def _receive(sqs, url: str) -> list:
    out = []
    for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                 MessageAttributeNames=["All"]).get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        attrs = {k: v.get("StringValue") for k, v in (m.get("MessageAttributes") or {}).items()}
        out.append((json.loads(m["Body"]), attrs))
    return out


def _await(sqs, url: str, match, timeout_s: float) -> tuple:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for body, attrs in _receive(sqs, url):
            if match(body, attrs):
                return body, attrs
    raise AssertionError(f"no matching message reached the queue within {timeout_s}s")


def _resend_until(events, sqs, bus, source, marker, url, timeout_s: float) -> dict:
    """Send events until one lands on ``url`` (queue-policy propagation); returns its body."""
    deadline = time.monotonic() + timeout_s
    sent: set = set()
    n = 0
    while time.monotonic() < deadline:
        n += 1
        sent.add(_put(events, bus, source, f"{marker}-{n}"))
        for body, _ in _receive(sqs, url):
            if body.get("id") in sent:
                return body
    raise AssertionError(f"after the queue policy was repaired no event reached the target in {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
