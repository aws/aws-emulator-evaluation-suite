"""cross-region-bus-target-delivers-to-the-other-regions-rules-with-the-source-region-and-a-new-event-id."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cross-region-bus-target-delivers-to-the-other-regions-rules-with-the-source-region-and-a-new-event-id"
GROUP = "bus-to-bus"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 240.0


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A rule targeting a custom bus in a second region forwards each matched event to that bus's
    rule and SQS target with the original source, detail-type, resources and detail, the ORIGIN
    region and this account, but a new EventId rather than the one PutEvents returned."""
    home = ctx.region
    away = _second_region(ctx)
    ev_home = ctx.client("events")
    ev_away = ctx.client("events", region=away)

    dst_bus, dst_arn = _create_bus(ctx, ev_away)
    assert dst_arn.split(":")[3] == away, (
        f"the bus created through the {away} endpoint has an ARN in region {dst_arn.split(':')[3]!r}"
    )
    queue_url, queue_arn = _create_queue(ctx, away)
    dst_rule = _create_rule(ctx, ev_away, dst_bus, {"source": [{"prefix": "sim2real.xregion."}]})
    put = ev_away.put_targets(Rule=dst_rule, EventBusName=dst_bus, Targets=[{"Id": "q", "Arn": queue_arn}])
    assert put["FailedEntryCount"] == 0, f"PutTargets in {away} failed: {put['FailedEntries']!r}"

    role_arn = _forwarding_role(ctx, dst_arn)
    src_bus, _ = _create_bus(ctx, ev_home)
    source = ctx.unique_name("sim2real.xregion.")
    src_rule = _create_rule(ctx, ev_home, src_bus, {"source": [source]})
    put = ev_home.put_targets(Rule=src_rule, EventBusName=src_bus, Targets=[
        {"Id": "away-bus", "Arn": dst_arn, "RoleArn": role_arn}])
    assert put["FailedEntryCount"] == 0, f"PutTargets in {home} failed: {put['FailedEntries']!r}"

    resource = f"arn:aws:s3:::{ctx.unique_name('sim2real-res-')}"
    sent: dict[str, str] = {}
    got: list[dict] = []
    sqs = ctx.client("sqs", region=away)
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    next_put = 0.0
    while time.monotonic() < deadline and not any(
            g["detail"].get("m") in sent.values() for g in got):
        if time.monotonic() >= next_put:
            # A just-created rule or role can drop events until delivery is live; re-publish.
            marker = ctx.unique_name("m-")
            resp = ev_home.put_events(Entries=[{
                "EventBusName": src_bus, "Source": source, "DetailType": "forwarded",
                "Detail": json.dumps({"m": marker, "n": 1}), "Resources": [resource]}])
            assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the entry: {resp['Entries']!r}"
            sent[resp["Entries"][0]["EventId"]] = marker
            next_put = time.monotonic() + 20.0
        for msg in sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=5).get("Messages", []):
            got.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    mine = [g for g in got if g["detail"].get("m") in sent.values()]
    assert mine, (
        f"no forwarded event reached the {away} queue within {_DELIVERY_TIMEOUT_S}s; "
        f"{len(sent)} event(s) sent from {home}, {len(got)} other message(s)"
    )
    env = mine[0]
    origin_id = next(eid for eid, m in sent.items() if m == env["detail"]["m"])
    assert sorted(env) == ["account", "detail", "detail-type", "id", "region", "resources",
                           "source", "time", "version"], f"the forwarded envelope has keys {sorted(env)!r}"
    assert (env["source"], env["detail-type"], env["resources"], env["account"]) == (
        source, "forwarded", [resource], ctx.account), (
        f"the forwarded envelope does not carry the original event: source match "
        f"{env['source'] == source!r}, detail-type {env['detail-type']!r}, resources match "
        f"{env['resources'] == [resource]!r}, account match {env['account'] == ctx.account!r}"
    )
    assert env["region"] == home, (
        f"the forwarded event's region must stay the origin region {home!r}; got {env['region']!r}"
    )
    assert env["id"] != origin_id, (
        "the event delivered in the second region carries the origin region's EventId; "
        "cross-region forwarding assigns a new one"
    )
    assert env["id"] not in sent, "the delivered id is one of the origin region's EventIds"


def _second_region(ctx) -> str:
    """A region that is NOT ctx.region and IS enabled for this account, derived at runtime; the
    same geography is preferred, and the choice is deterministic."""
    enabled = {r["RegionName"]: r.get("OptInStatus")
               for r in ctx.client("ec2").describe_regions()["Regions"]}
    candidates = sorted(n for n, s in enabled.items()
                        if n != ctx.region and s in ("opt-in-not-required", "opted-in"))
    assert candidates, f"no second region is enabled besides {ctx.region!r}; describe_regions said {enabled!r}"
    nearby = [n for n in candidates if n.split("-")[0] == ctx.region.split("-")[0]]
    return (nearby or candidates)[0]


def _create_bus(ctx, events) -> tuple[str, str]:
    bus = ctx.unique_name("sim2real-behav-bus-")
    arn = events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    return bus, arn


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


def _create_queue(ctx, region: str) -> tuple[str, str]:
    sqs = ctx.client("sqs", region=region)
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}}}]})})
    return url, arn


def _forwarding_role(ctx, bus_arn: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="forward", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="forward"))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
