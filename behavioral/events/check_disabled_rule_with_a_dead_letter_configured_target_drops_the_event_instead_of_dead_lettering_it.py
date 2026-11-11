"""disabled-rule-with-a-dead-letter-configured-target-drops-the-event-instead-of-dead-lettering-it."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "disabled-rule-with-a-dead-letter-configured-target-drops-the-event-instead-of-dead-lettering-it"
GROUP = "delivery-failure"
SERVICES = ["events"]

_SILENCE_WINDOW_S = 60.0
_DELIVERY_TIMEOUT_S = 150.0


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """While a rule is DISABLED, an event matching it never reaches its target's dead-letter queue; once
    ENABLED, the next matching event is dead-lettered with ERROR_CODE NO_PERMISSIONS, SQS's exact
    AccessDenied message and the rule's ARN, and the disabled-period event never appears."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    bus = ctx.unique_name("sim2real-evb-disdlq-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    source = ctx.unique_name("sim2real.disdlq.")
    rule = ctx.unique_name("sim2real-evb-disdlqrule-")
    rule_arn = events.put_rule(Name=rule, EventBusName=bus,
                               EventPattern=json.dumps({"source": [source]}))["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))

    bare_url, bare_arn = _queue(ctx, sqs, "bare")
    dlq_url, dlq_arn = _queue(ctx, sqs, "dlq")
    _set_policy(sqs, dlq_url, dlq_arn, rule_arn)

    retry = {"MaximumRetryAttempts": 185, "MaximumEventAgeInSeconds": 86400}
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": "bare", "Arn": bare_arn, "RetryPolicy": retry, "DeadLetterConfig": {"Arn": dlq_arn}},
    ])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["bare"]))
    assert put["FailedEntryCount"] == 0, f"PutTargets reported {put['FailedEntries']!r}"

    events.disable_rule(Name=rule, EventBusName=bus)
    described = events.describe_rule(Name=rule, EventBusName=bus)
    assert described["State"] == "DISABLED", f"the rule's State after DisableRule was {described['State']!r}"

    silent_id = _put(events, bus, source, ctx.unique_name("silent-"))
    seen_while_disabled = _drain_for(sqs, dlq_url, _SILENCE_WINDOW_S)
    assert silent_id not in {b.get("id") for b, _ in seen_while_disabled}, (
        f"a dead letter for the event sent while DISABLED arrived: {seen_while_disabled!r}"
    )
    assert seen_while_disabled == [], (
        f"the DLQ received {len(seen_while_disabled)} message(s) while the rule was disabled, expected none"
    )

    events.enable_rule(Name=rule, EventBusName=bus)
    described = events.describe_rule(Name=rule, EventBusName=bus)
    assert described["State"] == "ENABLED", f"the rule's State after EnableRule was {described['State']!r}"

    live_id = _put(events, bus, source, ctx.unique_name("live-"))
    passed_over: list = []
    body, attrs = _await(
        sqs, dlq_url, lambda b, a: b.get("id") == live_id, _DELIVERY_TIMEOUT_S, passed_over
    )
    assert attrs["ERROR_CODE"] == "NO_PERMISSIONS", (
        f"the always-failing target dead-lettered the post-enable event as {attrs['ERROR_CODE']!r}"
    )
    expected_message = (
        f"User: events.amazonaws.com is not authorized to perform: sqs:sendmessage on resource: "
        f"{bare_arn} because no resource-based policy allows the sqs:sendmessage action "
        f"(Service: AmazonSQS; Status Code: 403; Error Code: AccessDenied; Request ID: <id>; Proxy: null)"
    )
    assert _shaped(attrs["ERROR_MESSAGE"]) == expected_message, (
        f"the post-enable target's ERROR_MESSAGE was {_shaped(attrs['ERROR_MESSAGE'])!r}"
    )
    assert attrs["RULE_ARN"] == rule_arn, "the post-enable dead-letter RULE_ARN does not name the rule"

    leftover = passed_over + _drain_for(sqs, dlq_url, 20.0)
    assert silent_id not in {b.get("id") for b, _ in leftover}, (
        "the event sent while the rule was disabled arrived in the DLQ after a delay -- it was "
        "evaluated late rather than never evaluated"
    )


def _shaped(message: str) -> str:
    return re.sub(r"Request ID: [^;]+;", "Request ID: <id>;", message or "")


def _queue(ctx, sqs, label: str) -> tuple[str, str]:
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-evb-disdlq-{label}-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _set_policy(sqs, url: str, arn: str, rule_arn: str) -> None:
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})


def _put(events, bus: str, source: str, marker: str) -> str:
    resp = events.put_events(Entries=[{"EventBusName": bus, "Source": source, "DetailType": "sim2real-disdlq",
                                       "Detail": json.dumps({"marker": marker})}])
    assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
    return resp["Entries"][0]["EventId"]


def _receive(sqs, url: str) -> list:
    out = []
    for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                 MessageAttributeNames=["All"]).get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        body = json.loads(m["Body"])
        attrs = {k: v.get("StringValue") for k, v in (m.get("MessageAttributes") or {}).items()}
        out.append((body, attrs))
    return out


def _drain_for(sqs, url: str, window_s: float) -> list:
    out = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        out += _receive(sqs, url)
    return out


def _await(sqs, url: str, match, timeout_s: float, passed_over: list) -> tuple:
    """The first matching message; every other message received meanwhile goes to `passed_over`."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for body, attrs in _receive(sqs, url):
            if match(body, attrs):
                return body, attrs
            passed_over.append((body, attrs))
    raise AssertionError(f"no matching message reached the queue within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
