"""bus-target-without-role-arn-rejected-in-both-regions-and-the-rule-keeps-its-targets."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bus-target-without-role-arn-rejected-in-both-regions-and-the-rule-keeps-its-targets"
GROUP = "bus-to-bus"
SERVICES = ["events"]

_DELIVERY_TIMEOUT_S = 150.0


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """PutTargets naming a custom bus (this or a second region) without RoleArn is refused with
    "RoleArn is required for target <bus arn>." while the valid SQS target in the same request is
    kept and still delivers; the same bus target with a RoleArn is accepted."""
    events = ctx.client("events")
    away = _second_region(ctx)
    ev_away = ctx.client("events", region=away)

    _, same_arn = _create_bus(ctx, events)
    _, away_arn = _create_bus(ctx, ev_away)
    queue_url, queue_arn = _create_queue(ctx)
    bus, _ = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.busrole.")
    rule = _create_rule(ctx, events, bus, {"source": [source]})
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "q", "Arn": queue_arn}])
    assert put["FailedEntryCount"] == 0, f"PutTargets of the SQS target failed: {put['FailedEntries']!r}"

    for label, target_arn in (("same-region", same_arn), ("cross-region", away_arn)):
        code, msg = _error(lambda: events.put_targets(Rule=rule, EventBusName=bus, Targets=[
            {"Id": "q", "Arn": queue_arn}, {"Id": "bus", "Arn": target_arn}]))
        assert code == "ValidationException", f"the {label} bus target without RoleArn gave {code!r}"
        assert msg == f"RoleArn is required for target {target_arn}.", (
            f"the {label} refusal message was {msg!r}"
        )
        ids = sorted(t["Id"] for t in events.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"])
        assert ids == ["q"], f"after the refused {label} PutTargets the rule lists targets {ids!r}"

    # Positive control: the rule's surviving target still delivers.
    _publish_until_delivered(ctx, events, bus, source, queue_url)

    role_arn = _role(ctx, [same_arn, away_arn])
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": "same", "Arn": same_arn, "RoleArn": role_arn},
        {"Id": "away", "Arn": away_arn, "RoleArn": role_arn}])
    assert put["FailedEntryCount"] == 0, (
        f"bus targets with a RoleArn must be accepted: {put['FailedEntries']!r}"
    )
    targets = {t["Id"]: t for t in events.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"]}
    assert sorted(targets) == ["away", "q", "same"], f"the rule lists targets {sorted(targets)!r}"
    assert (targets["same"].get("RoleArn"), targets["away"].get("RoleArn")) == (role_arn, role_arn), (
        "the accepted bus targets do not read back with the RoleArn they were given"
    )


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call succeeded; real AWS refuses it")


def _second_region(ctx) -> str:
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


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
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


def _role(ctx, bus_arns: list[str]) -> str:
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
            "Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arns}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="forward"))
    return arn


def _publish_until_delivered(ctx, events, bus: str, source: str, queue_url: str) -> None:
    sqs = ctx.client("sqs")
    sent: set[str] = set()
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    next_put = 0.0
    while time.monotonic() < deadline:
        if time.monotonic() >= next_put:
            resp = events.put_events(Entries=[{"EventBusName": bus, "Source": source,
                                               "DetailType": "control", "Detail": "{}"}])
            sent.add(resp["Entries"][0]["EventId"])
            next_put = time.monotonic() + 15.0
        for msg in sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=5).get("Messages", []):
            if json.loads(msg["Body"]).get("id") in sent:
                return
    raise AssertionError(
        f"the rule's SQS target delivered none of {len(sent)} control event(s) within "
        f"{_DELIVERY_TIMEOUT_S}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
