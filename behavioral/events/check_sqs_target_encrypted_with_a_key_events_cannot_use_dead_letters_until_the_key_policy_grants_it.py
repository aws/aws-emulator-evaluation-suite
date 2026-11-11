"""sqs-target-encrypted-with-a-key-events-cannot-use-dead-letters-until-the-key-policy-grants-it."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "sqs-target-encrypted-with-a-key-events-cannot-use-dead-letters-until-the-key-policy-grants-it"
GROUP = "delivery-failure"
SERVICES = ["events"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An SQS target encrypted with a key events.amazonaws.com may not use is dead-lettered as NO_PERMISSIONS
    with KMS's message and stays empty while a healthy sibling receives; granting kms:GenerateDataKey and
    kms:Decrypt to events.amazonaws.com in the key policy lets the same target receive."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")

    root = {"Sid": "Root", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "kms:*", "Resource": "*"}
    key_id = kms.create_key(Description=f"sim2real {CHECK}",
                            Policy=json.dumps({"Version": "2012-10-17", "Statement": [root]}),
                            Tags=[{"TagKey": "sim2real", "TagValue": CHECK}])["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    bus = ctx.unique_name("sim2real-evb-kmsq-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    source = ctx.unique_name("sim2real.kmsq.")
    rule = ctx.unique_name("sim2real-evb-kmsrule-")
    rule_arn = events.put_rule(Name=rule, EventBusName=bus,
                               EventPattern=json.dumps({"source": [source]}))["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))

    enc_url, enc_arn = _queue(ctx, sqs, "enc", rule_arn, {"KmsMasterKeyId": key_id})
    ok_url, ok_arn = _queue(ctx, sqs, "ok", rule_arn, {})
    dlq_url, dlq_arn = _queue(ctx, sqs, "dlq", rule_arn, {})
    resp = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": "enc", "Arn": enc_arn, "DeadLetterConfig": {"Arn": dlq_arn}},
        {"Id": "ok", "Arn": ok_arn},
    ])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["enc", "ok"]))
    assert resp["FailedEntryCount"] == 0, f"PutTargets reported {resp['FailedEntries']!r}"

    event_id = _put(events, bus, source, ctx.unique_name("m-"))
    healthy, _ = _await(sqs, ok_url, lambda b, a: b.get("id") == event_id, 90.0)
    body, attrs = _await(sqs, dlq_url, lambda b, a: b.get("id") == event_id, 120.0)
    assert attrs.get("ERROR_CODE") == "NO_PERMISSIONS", f"dead-letter ERROR_CODE was {attrs.get('ERROR_CODE')!r}"
    # The message embeds two minted request ids; they are shaped, everything else is exact.
    shaped = re.sub(r"Request ID: [^;]+;", "Request ID: <id>;", attrs.get("ERROR_MESSAGE") or "")
    assert shaped == _EXPECTED_KMS_MESSAGE, f"dead-letter ERROR_MESSAGE was {shaped!r}"
    assert attrs.get("TARGET_ARN") == enc_arn, "dead-letter TARGET_ARN does not name the encrypted queue"
    assert attrs.get("RULE_ARN") == rule_arn, "dead-letter RULE_ARN does not name the rule"
    assert body == healthy, "the dead-lettered body differs from the event the healthy target received"
    left = sqs.receive_message(QueueUrl=enc_url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
    assert left == [], f"the encrypted queue holds {len(left)} message(s) despite the key refusing EventBridge"

    grant = {"Sid": "EventBridge", "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
             "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": "*"}
    kms.put_key_policy(KeyId=key_id, PolicyName="default",
                       Policy=json.dumps({"Version": "2012-10-17", "Statement": [root, grant]}))
    got = _resend_until(events, sqs, bus, source, ctx.unique_name("m2-"), enc_url, timeout_s=180.0)
    assert got["source"] == source, f"event delivered after the key grant had source {got['source']!r}"


# The dead-letter ERROR_MESSAGE EventBridge records when SQS cannot use the key on its behalf.
_EXPECTED_KMS_MESSAGE = (
    "User: events.amazonaws.com is not authorized to perform: kms:GenerateDataKey on this resource "
    "because the resource does not exist in this Region, no resource-based policies allow access, or a "
    "resource-based policy explicitly denies access (Service: AWSKMS; Status Code: 400; Error Code: "
    "AccessDeniedException; Request ID: <id>; Proxy: null) (Service: AmazonSQS; Status Code: 400; "
    "Error Code: KMS.AccessDeniedException; Request ID: <id>; Proxy: null)"
)


def _queue(ctx, sqs, label: str, rule_arn: str, attributes: dict) -> tuple[str, str]:
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-evb-{label}-"), Attributes=attributes,
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})
    return url, arn


def _put(events, bus: str, source: str, marker: str) -> str:
    resp = events.put_events(Entries=[{"EventBusName": bus, "Source": source, "DetailType": "sim2real-kms",
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
    """Send events until one lands on ``url`` (key-policy propagation); returns its body."""
    deadline = time.monotonic() + timeout_s
    sent: set = set()
    n = 0
    while time.monotonic() < deadline:
        n += 1
        sent.add(_put(events, bus, source, f"{marker}-{n}"))
        for body, _ in _receive(sqs, url):
            if body.get("id") in sent:
                return body
    raise AssertionError(f"after the key policy grant no event reached the encrypted target in {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
