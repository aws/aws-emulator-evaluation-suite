"""custom-bus-addressed-by-arn-is-the-same-bus-as-by-name."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "custom-bus-addressed-by-arn-is-the-same-bus-as-by-name"
GROUP = "event-bus"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 90.0


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "concern:representation",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A custom bus addressed by ARN is the same bus as by name: DescribeEventBus(Name=<arn>)
    returns it, a rule created by ARN is listed by name, and an event put by ARN arrives with the
    same envelope as one put by name. IaC tools commonly pass the bus ARN rather than its name."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    by_arn = events.describe_event_bus(Name=bus_arn)
    assert (by_arn["Name"], by_arn["Arn"]) == (bus, bus_arn), (
        f"DescribeEventBus by ARN must return the named bus, got {(by_arn['Name'], by_arn['Arn'])!r}"
    )

    source = ctx.unique_name("sim2real.byarn.")
    rule = ctx.unique_name("sim2real-behav-rule-")
    rule_arn = events.put_rule(Name=rule, EventBusName=bus_arn, EventPattern=json.dumps({"source": [source]}))["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))
    assert rule_arn == f"arn:aws:events:{ctx.region}:{ctx.account}:rule/{bus}/{rule}", (
        f"a rule created on the bus ARN must carry the bus NAME in its ARN, got {rule_arn!r}"
    )
    by_name = [r["Name"] for r in events.list_rules(EventBusName=bus, NamePrefix=rule)["Rules"]]
    assert by_name == [rule], f"the rule created via the bus ARN must be listed under the bus name, got {by_name!r}"

    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage",
        "Resource": queue_arn, "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})
    events.put_targets(Rule=rule, EventBusName=bus_arn, Targets=[{"Id": "sim2real-q", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, EventBusName=bus, Ids=["sim2real-q"]))
    targets = [t["Arn"] for t in events.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"]]
    assert targets == [queue_arn], f"the target added via the bus ARN must be listed under the name, got {targets!r}"

    sent = {}
    for spelling, address in (("arn", bus_arn), ("name", bus)):
        resp = events.put_events(Entries=[{"EventBusName": address, "Source": source, "DetailType": "sim2real-byarn",
                                           "Detail": json.dumps({"spelling": spelling})}])
        assert resp["FailedEntryCount"] == 0, f"PutEvents by {spelling} was refused: {resp['Entries']!r}"
        sent[resp["Entries"][0]["EventId"]] = spelling

    received = _receive(sqs, url, set(sent))
    assert set(received) == set(sent), (
        f"events put by ARN and by name must both be delivered; got {sorted(received[i]['detail']['spelling'] for i in received)!r}"
    )
    for event_id, body in received.items():
        assert body["detail"] == {"spelling": sent[event_id]}, f"detail mismatch for the {sent[event_id]} event"
        assert (body["account"], body["region"], body["source"]) == (ctx.account, ctx.region, source), (
            f"the {sent[event_id]}-addressed event's envelope must name this account, region and source"
        )


def _receive(sqs, url: str, ids: set) -> dict:
    found: dict = {}
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    while time.monotonic() < deadline and set(found) != ids:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get("Messages", []):
            body = json.loads(m["Body"])
            if body.get("id") in ids:
                found[body["id"]] = body
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
