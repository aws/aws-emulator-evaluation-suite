"""sns-target-on-a-kms-encrypted-topic-dead-letters-as-no-permissions-until-the-key-policy-grants-events."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "sns-target-on-a-kms-encrypted-topic-dead-letters-as-no-permissions-until-the-key-policy-grants-events"
GROUP = "sns-target"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 180.0
_GRANT_TIMEOUT_S = 300.0

_KMS_DENIED = (
    "User: events.amazonaws.com is not authorized to perform: kms:GenerateDataKey on this "
    "resource because the resource does not exist in this Region, no resource-based policies "
    "allow access, or a resource-based policy explicitly denies access (Service: AWSKMS; Status "
    "Code: 400; Error Code: AccessDeniedException; Request ID: <id>; Proxy: null) (Service: "
    "AmazonSNS; Status Code: 400; Error Code: KMSAccessDenied; Request ID: <id>; Proxy: null)"
)


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An SNS target on a CMK-encrypted topic dead-letters events as NO_PERMISSIONS with the KMS
    denial while the key policy excludes events.amazonaws.com, and publishes once it is granted.
    """
    events = ctx.client("events")
    kms = ctx.client("kms")
    key_id = kms.create_key(Description=f"sim2real-behav {CHECK}",
                            Tags=[{"TagKey": "sim2real", "TagValue": CHECK}])["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    topic_arn = _create_topic(ctx, key_id)
    sub_url = _subscribe_queue(ctx, topic_arn)
    dlq_url, dlq_arn = _create_dlq(ctx)

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.snskms.")
    rule, rule_arn = _create_rule(ctx, events, bus, {"source": [source]})
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[{
        "Id": "topic", "Arn": topic_arn, "DeadLetterConfig": {"Arn": dlq_arn},
        "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}}])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    # The default key policy grants only the account root. A dead letter for one of our
    # events also proves the rule is live.
    dead: list[dict] = []
    sent: set[str] = set()
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    next_put = 0.0
    while time.monotonic() < deadline and not any(d["body"].get("id") in sent for d in dead):
        if time.monotonic() >= next_put:
            sent.add(_publish(events, bus, source, "denied"))
            next_put = time.monotonic() + 20.0
        dead += _receive(ctx, dlq_url)
    mine = [d for d in dead if d["body"].get("id") in sent]
    assert mine, f"no dead letter arrived within {_DELIVERY_TIMEOUT_S}s for the {len(sent)} event(s) sent"
    attrs = mine[0]["attrs"]
    shaped = re.sub(r"Request ID: [^;]+;", "Request ID: <id>;", attrs.get("ERROR_MESSAGE") or "")
    assert attrs.get("ERROR_CODE") == "NO_PERMISSIONS", f"dead-letter ERROR_CODE was {attrs.get('ERROR_CODE')!r}"
    assert shaped == _KMS_DENIED, f"dead-letter ERROR_MESSAGE was {shaped!r}"
    assert (attrs.get("RULE_ARN"), attrs.get("TARGET_ARN")) == (rule_arn, topic_arn), (
        f"the dead letter names rule match {attrs.get('RULE_ARN') == rule_arn!r}, "
        f"target match {attrs.get('TARGET_ARN') == topic_arn!r}"
    )
    leaked = [n for n in _receive_for(ctx, sub_url, 10.0) if _note_id(n) in sent]
    assert leaked == [], f"the subscriber received {len(leaked)} denied event(s)"

    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Sid": "root", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "events", "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
             "Action": ["kms:GenerateDataKey*", "kms:Decrypt"], "Resource": "*"}]}))
    granted: set[str] = set()
    notes: list[dict] = []
    deadline = time.monotonic() + _GRANT_TIMEOUT_S
    next_put = 0.0
    # The key policy change takes effect after a propagation delay that exposes no condition
    # to poll; re-publish until a granted event reaches the subscriber.
    while time.monotonic() < deadline and not any(_note_id(n) in granted for n in notes):
        if time.monotonic() >= next_put:
            granted.add(_publish(events, bus, source, "granted"))
            next_put = time.monotonic() + 20.0
        notes += _receive(ctx, sub_url)
    got = [n for n in notes if _note_id(n) in granted]
    assert got, (
        f"after the key policy granted events.amazonaws.com, none of {len(granted)} event(s) "
        f"reached the subscriber within {_GRANT_TIMEOUT_S}s"
    )
    env = json.loads(got[0]["body"]["Message"])
    assert (env["source"], env["detail"]) == (source, {"phase": "granted"}), (
        f"the published event is not the one sent: {env!r}"
    )


def _publish(events, bus: str, source: str, phase: str) -> str:
    resp = events.put_events(Entries=[{"EventBusName": bus, "Source": source, "DetailType": "kms",
                                       "Detail": json.dumps({"phase": phase})}])
    assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
    return resp["Entries"][0]["EventId"]


def _note_id(note: dict) -> str | None:
    try:
        return json.loads(note["body"]["Message"]).get("id")
    except (KeyError, ValueError, AttributeError):
        return None


def _create_topic(ctx, key_id: str) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-topic-"),
                           Attributes={"KmsMasterKeyId": key_id},
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    sns.set_topic_attributes(TopicArn=arn, AttributeName="Policy", AttributeValue=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sns:Publish", "Resource": arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}}}]}))
    return arn


def _subscribe_queue(ctx, topic_arn: str) -> str:
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]})})
    sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=arn,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))
    return url


def _create_dlq(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-dlq-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}}}]})})
    return url, arn


def _create_bus(ctx, events) -> str:
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    return bus


def _create_rule(ctx, events, bus: str, pattern: dict) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-behav-rule-")
    arn = events.put_rule(Name=name, EventBusName=bus, EventPattern=json.dumps(pattern))["RuleArn"]

    def _delete() -> None:
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=name, EventBusName=bus)["Targets"]]
        if ids:
            events.remove_targets(Rule=name, EventBusName=bus, Ids=ids)
        events.delete_rule(Name=name, EventBusName=bus)

    ctx.on_cleanup(_delete)
    return name, arn


def _receive(ctx, url: str) -> list[dict]:
    sqs = ctx.client("sqs")
    out = []
    for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                   MessageAttributeNames=["All"]).get("Messages", []):
        out.append({"body": json.loads(msg["Body"]),
                    "attrs": {k: v.get("StringValue") for k, v in msg.get("MessageAttributes", {}).items()}})
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _receive_for(ctx, url: str, seconds: float) -> list[dict]:
    out: list[dict] = []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        out += _receive(ctx, url)
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
