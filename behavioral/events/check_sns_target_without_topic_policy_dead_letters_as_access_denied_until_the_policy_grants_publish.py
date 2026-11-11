"""sns-target-without-topic-policy-dead-letters-as-access-denied-until-the-policy-grants-publish."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "sns-target-without-topic-policy-dead-letters-as-access-denied-until-the-policy-grants-publish"
GROUP = "sns-target"
SERVICES = ["events"]

_DEAD_LETTER_KEYS = ["ERROR_CODE", "ERROR_MESSAGE", "RULE_ARN", "TARGET_ARN"]
_DELIVERY_TIMEOUT_S = 180.0


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An SNS target whose topic policy lacks a Publish grant for events.amazonaws.com is dead-lettered as
    NO_PERMISSIONS with SNS's AccessDenied message, rule and topic ARNs, while a healthy sibling receives the
    event; adding the Publish statement lets the next event reach the topic's subscribed queue."""
    events = ctx.client("events")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    bus = ctx.unique_name("sim2real-evb-snsdlq-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    source = ctx.unique_name("sim2real.snsdlq.")
    rule = ctx.unique_name("sim2real-evb-snsdlqrule-")
    rule_arn = events.put_rule(Name=rule, EventBusName=bus,
                               EventPattern=json.dumps({"source": [source]}))["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-evb-snsdlq-topic-"),
                                 Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    healthy_url, healthy_arn = _queue(ctx, sqs, "ok")
    dlq_url, dlq_arn = _queue(ctx, sqs, "dlq")
    _set_sqs_policy(sqs, healthy_url, healthy_arn, rule_arn, "Allow")
    _set_sqs_policy(sqs, dlq_url, dlq_arn, rule_arn, "Allow")

    retry = {"MaximumRetryAttempts": 180, "MaximumEventAgeInSeconds": 86400}
    resp = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": "denied", "Arn": topic_arn, "RetryPolicy": retry, "DeadLetterConfig": {"Arn": dlq_arn}},
        {"Id": "healthy", "Arn": healthy_arn},
    ])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["denied", "healthy"]))
    assert resp["FailedEntryCount"] == 0, f"PutTargets reported {resp['FailedEntries']!r}"

    event_id = _put(events, bus, source, ctx.unique_name("m-"))
    healthy, _ = _await_sqs(sqs, healthy_url, lambda b, a: b.get("id") == event_id, _DELIVERY_TIMEOUT_S)

    body, attrs = _await_sqs(sqs, dlq_url, lambda b, a: b.get("id") == event_id, _DELIVERY_TIMEOUT_S)
    assert sorted(attrs) == _DEAD_LETTER_KEYS, f"the denied target's dead-letter attributes were {sorted(attrs)!r}"
    assert attrs["ERROR_CODE"] == "NO_PERMISSIONS", (
        f"an SNS target with no resource policy dead-lettered as {attrs['ERROR_CODE']!r}"
    )
    assert _shaped(attrs["ERROR_MESSAGE"]) == _ACCESS_DENIED, (
        f"the denied target's ERROR_MESSAGE was {_shaped(attrs['ERROR_MESSAGE'])!r}"
    )
    assert attrs["RULE_ARN"] == rule_arn, "the denied target's dead-letter RULE_ARN does not name the rule"
    assert attrs["TARGET_ARN"] == topic_arn, "the denied target's dead-letter TARGET_ARN does not name the topic"
    assert body == healthy, "the dead-lettered body differs from the event delivered to the healthy sibling"

    # Repair: subscribe a queue to the topic and grant the withheld statement.
    sub_url, sub_arn = _queue(ctx, sqs, "sub")
    sqs.set_queue_attributes(QueueUrl=sub_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": sub_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]})})
    sub_id = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=sub_arn,
                           ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_id))
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sns:Publish", "Resource": topic_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]}))

    marker2 = ctx.unique_name("m2-")
    published = _resend_until_notified(events, sqs, bus, source, marker2, sub_url, timeout_s=150.0)
    assert published is not None, "after the policy was repaired no notification reached the subscriber"
    env = json.loads(published["Message"])
    assert env["source"] == source, f"the repaired delivery's envelope had source {env['source']!r}"


# SNS's own AccessDenied as EventBridge records it; the minted request id is shaped.
_ACCESS_DENIED = (
    "User: <id> is not authorized to perform: SNS:Publish on resource: "
    "<id> because no resource-based policy allows the SNS:Publish action (Service: AmazonSNS; "
    "Status Code: 403; Error Code: AuthorizationError; Request ID: <id>; Proxy: null)"
)


def _shaped(message: str) -> str:
    message = re.sub(r"Request ID: [^;]+;", "Request ID: <id>;", message or "")
    message = re.sub(r"User: [^ ]+ is not authorized", "User: <id> is not authorized", message)
    message = re.sub(r"on resource: [^ ]+ because", "on resource: <id> because", message)
    return message


def _queue(ctx, sqs, label: str) -> tuple[str, str]:
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-evb-snsdlq-{label}-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _set_sqs_policy(sqs, url: str, arn: str, rule_arn: str, effect: str) -> None:
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": effect, "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})


def _put(events, bus: str, source: str, marker: str) -> str:
    resp = events.put_events(Entries=[{"EventBusName": bus, "Source": source, "DetailType": "sim2real-snsdlq",
                                       "Detail": json.dumps({"marker": marker})}])
    assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
    return resp["Entries"][0]["EventId"]


def _receive_sqs(sqs, url: str) -> list:
    out = []
    for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                 MessageAttributeNames=["All"]).get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        body = json.loads(m["Body"])
        attrs = {k: v.get("StringValue") for k, v in (m.get("MessageAttributes") or {}).items()}
        out.append((body, attrs))
    return out


def _await_sqs(sqs, url: str, match, timeout_s: float) -> tuple:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for body, attrs in _receive_sqs(sqs, url):
            if match(body, attrs):
                return body, attrs
    raise AssertionError(f"no matching message reached the queue within {timeout_s}s")


def _resend_until_notified(events, sqs, bus, source, marker, sub_url, timeout_s: float):
    """Send events until a notification reaches ``sub_url`` (SNS policy propagation)."""
    deadline = time.monotonic() + timeout_s
    n = 0
    while time.monotonic() < deadline:
        n += 1
        _put(events, bus, source, f"{marker}-{n}")
        for m in sqs.receive_message(QueueUrl=sub_url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=5).get("Messages", []):
            sqs.delete_message(QueueUrl=sub_url, ReceiptHandle=m["ReceiptHandle"])
            note = json.loads(m["Body"])
            if note.get("Type") == "Notification":
                return note
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
