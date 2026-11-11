"""sns-target-publishes-the-compact-envelope-and-a-plain-text-template-keeps-its-quotes."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sns-target-publishes-the-compact-envelope-and-a-plain-text-template-keeps-its-quotes"
GROUP = "sns-target"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 180.0


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two SNS targets on one topic publish one notification each: the raw target's Message is the
    compact nine-key event envelope, and a plain-text template keeps its double quotes; neither
    notification carries a Subject or MessageAttributes.
    """
    events = ctx.client("events")
    topic_arn = _create_topic(ctx)
    sub_url = _subscribe_queue(ctx, topic_arn)

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.sns.")
    rule = _create_rule(ctx, events, bus, {"source": [source]})
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": "raw", "Arn": topic_arn},
        {"Id": "text", "Arn": topic_arn, "InputTransformer": {
            "InputPathsMap": {"m": "$.detail.m"}, "InputTemplate": '"order <m> placed"'}},
    ])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    resource = f"arn:aws:s3:::{ctx.unique_name('sim2real-res-')}"
    notes: list[dict] = []
    sent: dict[str, str] = {}

    def _pair() -> str | None:
        for eid, marker in sent.items():
            has_raw = any(_raw_id(n) == eid for n in notes)
            has_text = any(n["Message"] == f'"order {marker} placed"' for n in notes)
            if has_raw and has_text:
                return eid
        return None

    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    next_put = 0.0
    while time.monotonic() < deadline and _pair() is None:
        if time.monotonic() >= next_put:
            # A just-created rule can drop events until routing is live; re-publish.
            marker = ctx.unique_name("m-")
            resp = events.put_events(Entries=[{
                "EventBusName": bus, "Source": source, "DetailType": "order.placed",
                "Detail": json.dumps({"m": marker, "qty": 2}), "Resources": [resource]}])
            assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
            sent[resp["Entries"][0]["EventId"]] = marker
            next_put = time.monotonic() + 20.0
        notes += _receive(ctx, sub_url)
    event_id = _pair()
    assert event_id is not None, (
        f"no event produced both notifications within {_DELIVERY_TIMEOUT_S}s; "
        f"{len(notes)} notification(s) received"
    )
    marker = sent[event_id]
    raw = next(n for n in notes if _raw_id(n) == event_id)
    text = next(n for n in notes if n["Message"] == f'"order {marker} placed"')

    env = json.loads(raw["Message"])
    assert raw["Message"] == json.dumps(env, separators=(",", ":")), (
        f"the raw target's Message is not compact JSON: {raw['Message'][:200]!r}"
    )
    assert sorted(list(env)) == sorted(["version", "id", "detail-type", "source", "account", "time",
                                        "region", "resources", "detail"]), (
        f"the published envelope's keys are {list(env)!r}"
    )
    assert (env["source"], env["detail-type"], env["resources"], env["detail"], env["account"],
            env["region"]) == (source, "order.placed", [resource], {"m": marker, "qty": 2},
                               ctx.account, ctx.region), (
        f"the published envelope is not the event: {env!r}"
    )
    for label, note in (("raw", raw), ("text", text)):
        assert (note["Type"], note["TopicArn"]) == ("Notification", topic_arn), (
            f"the {label} notification is a {note['Type']!r} from topic match "
            f"{note['TopicArn'] == topic_arn!r}"
        )
        assert "Subject" not in note and "MessageAttributes" not in note, (
            f"the {label} notification carries Subject={note.get('Subject')!r} "
            f"MessageAttributes={note.get('MessageAttributes')!r}"
        )
    assert raw["MessageId"] != text["MessageId"], "the two targets' notifications share a MessageId"


def _raw_id(note: dict) -> str | None:
    try:
        body = json.loads(note["Message"])
    except ValueError:
        return None
    return body.get("id") if isinstance(body, dict) else None


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-topic-"),
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


def _create_bus(ctx, events) -> str:
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    return bus


def _create_rule(ctx, events, bus: str, pattern: dict) -> str:
    name = ctx.unique_name("sim2real-behav-rule-")
    events.put_rule(Name=name, EventBusName=bus, EventPattern=json.dumps(pattern))

    def _delete() -> None:
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=name, EventBusName=bus)["Targets"]]
        if ids:
            events.remove_targets(Rule=name, EventBusName=bus, Ids=ids)
        events.delete_rule(Name=name, EventBusName=bus)

    ctx.on_cleanup(_delete)
    return name


def _receive(ctx, url: str) -> list[dict]:
    sqs = ctx.client("sqs")
    out = []
    for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=5).get("Messages", []):
        out.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
