"""non-matching-event-pattern-delivers-nothing-to-its-target."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "non-matching-event-pattern-delivers-nothing-to-its-target"
GROUP = 'fanout'
SERVICES = ['events', 'sqs']

N_EVENTS = 300
N_TENANTS = 20
N_CONTROL_EVENTS = 60
SOURCE = "sim2real.d5"
DETAIL_TYPE = "sim2real.ordering"

#: The probe rule's first pattern matches no tenant this workload ever publishes; its second
#: matches every one of them. Same rule, same target, same queue, same policy — so the only
#: thing that changes between "nothing arrives" and "everything arrives" is the pattern.
NEVER = {"source": [SOURCE], "detail": {"tenant": [{"prefix": "zzz-never-"}]}}
ALWAYS = {"source": [SOURCE], "detail": {"tenant": [{"prefix": "t-0"}]}}
ALL_EVENTS = {"source": [SOURCE], "detail-type": [DETAIL_TYPE]}


_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


def _queue(sqs, ctx, region: str, account: str, bus: str) -> tuple[str, str]:
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-d5-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowEventBridge", "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnLike": {
                "aws:SourceArn": f"arn:aws:events:{region}:{account}:rule/{bus}/*"}},
        }],
    })})
    return url, arn


def _publish(ev, bus: str, payloads: list[tuple[str, str, int]]) -> None:
    for base in range(0, len(payloads), 10):
        batch = payloads[base:base + 10]
        resp = ev.put_events(Entries=[
            {"EventBusName": bus, "Source": SOURCE, "DetailType": DETAIL_TYPE,
             "Detail": json.dumps({"tenant": tenant, "n": n, "id": event_id})}
            for event_id, tenant, n in batch])
        assert resp["FailedEntryCount"] == 0, (
            f"put_events at offset {base} reported {resp['FailedEntryCount']} failures: {resp!r}"
        )


def _receive(sqs, url: str, wait: int = 5) -> list[str]:
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
    msgs = resp.get("Messages", [])
    if msgs:
        sqs.delete_message_batch(QueueUrl=url, Entries=[
            {"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])
    return [json.loads(m["Body"])["detail"]["id"] for m in msgs]


def _collect(sqs, url: str, want: int, budget_s: float) -> list[str]:
    got: list[str] = []
    idle = 0
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline and len(got) < want:
        batch = _receive(sqs, url)
        if not batch:
            idle += 1
            if idle >= 8:
                return got
            continue
        idle = 0
        got += batch
    return got


def _drain_empty(sqs, url: str) -> None:
    empties = 0
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and empties < 2:
        empties = empties + 1 if not _receive(sqs, url, wait=2) else 0
    assert empties >= 2, f"queue {url!r} would not drain to empty inside 120 s"


def _warm_up(ev, sqs, bus: str, url: str) -> None:
    """Publish throwaway events until this queue proves it can receive one.

    An SQS resource policy becomes effective asynchronously and exposes no condition to poll,
    and EventBridge drops what it cannot deliver with FailedEntryCount 0 — which would look
    exactly like the absence this check asserts. So the absence is only meaningful after a
    delivery has been OBSERVED through the same bus, rule surface and policy.
    """
    deadline = time.monotonic() + 240
    round_no = 0
    while time.monotonic() < deadline:
        _publish(ev, bus, [(f"warm-{round_no}", "t-000", 0)])
        round_no += 1
        for _ in range(5):
            if _receive(sqs, url, wait=2):
                _drain_empty(sqs, url)
                return
    raise AssertionError(
        f"the control queue never received a warm-up event in 240 s, so no later absence could "
        f"be attributed to a pattern"
    )


@tags(
    "axis:negative-delivery",
    "cap:c2",
    "cap:c3",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A rule whose pattern matches none of 300 events delivers none to its queue while a neighbour rule
    on the same bus receives all 300; repointed at a matching pattern, the same rule and target then
    receive all 60 control events. PutEvents reports FailedEntryCount 0 either way."""
    ev = ctx.client("events")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bus = ctx.unique_name("sim2real-behav-d5-")
    ev.create_event_bus(Name=bus, Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])
    ctx.on_cleanup(lambda: ev.delete_event_bus(Name=bus))

    control_url, control_arn = _queue(sqs, ctx, ctx.region, account, bus)
    probe_url, probe_arn = _queue(sqs, ctx, ctx.region, account, bus)

    control_rule, probe_rule = f"{bus}-control", f"{bus}-probe"
    for rule, pattern, arn in ((control_rule, ALL_EVENTS, control_arn),
                               (probe_rule, NEVER, probe_arn)):
        ev.put_rule(Name=rule, EventBusName=bus, EventPattern=json.dumps(pattern), State="ENABLED",
                    Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])
        ctx.on_cleanup(lambda r=rule: ev.delete_rule(Name=r, EventBusName=bus))
        resp = ev.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "q", "Arn": arn}])
        ctx.on_cleanup(lambda r=rule: ev.remove_targets(Rule=r, EventBusName=bus, Ids=["q"]))
        assert resp["FailedEntryCount"] == 0, (
            f"put_targets for {rule} failed: {resp.get('FailedEntries')!r}"
        )
    assert [t["Arn"] for t in ev.list_targets_by_rule(
        Rule=probe_rule, EventBusName=bus)["Targets"]] == [probe_arn], (
        "the probe rule does not have exactly the probe queue as its target, so a zero would "
        "prove nothing"
    )

    _warm_up(ev, sqs, bus, control_url)

    published = [(f"{bus}-{i:04d}", f"t-{i % N_TENANTS:03d}", i) for i in range(N_EVENTS)]
    ids = {event_id for event_id, _t, _n in published}
    _publish(ev, bus, published)

    # ---- the live control: every event reaches the neighbouring rule's queue -------------- #
    delivered = _collect(sqs, control_url, N_EVENTS, 240.0)
    assert set(delivered) == ids, (
        f"the control rule received {len(set(delivered))} of {N_EVENTS} events, so delivery was "
        f"not working during the window in which the probe queue stayed empty; missing "
        f"{sorted(ids - set(delivered))[:5]!r}"
    )

    # ---- the effect is absent: nothing reached the non-matching rule's queue -------------- #
    leaked = _collect(sqs, probe_url, 1, 90.0)
    assert leaked == [], (
        f"a rule whose pattern matches no published tenant delivered {len(leaked)} events: "
        f"{leaked[:5]!r}"
    )
    depth = sqs.get_queue_attributes(
        QueueUrl=probe_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    assert depth == {"ApproximateNumberOfMessages": "0",
                     "ApproximateNumberOfMessagesNotVisible": "0"}, (
        f"the non-matching rule's queue reports {depth!r}, not empty"
    )

    # ---- positive control on the SAME rule and target: a matching pattern delivers -------- #
    ev.put_rule(Name=probe_rule, EventBusName=bus, EventPattern=json.dumps(ALWAYS),
                State="ENABLED")
    assert [t["Arn"] for t in ev.list_targets_by_rule(
        Rule=probe_rule, EventBusName=bus)["Targets"]] == [probe_arn], (
        "updating the pattern dropped the rule's target, so the control would be untestable"
    )
    control_events = [(f"{bus}-c{i:03d}", f"t-{i % N_TENANTS:03d}", i)
                      for i in range(N_CONTROL_EVENTS)]
    control_ids = {event_id for event_id, _t, _n in control_events}
    arrived: set[str] = set()
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline and arrived != control_ids:
        _publish(ev, bus, control_events)
        arrived |= {event_id for event_id in _collect(sqs, probe_url, N_CONTROL_EVENTS, 45.0)
                    if event_id in control_ids}
    assert arrived == control_ids, (
        f"after the SAME rule and target were repointed at a matching pattern, only "
        f"{len(arrived)} of {N_CONTROL_EVENTS} events arrived — the earlier zero cannot be "
        f"attributed to the pattern; missing {sorted(control_ids - arrived)[:5]!r}"
    )
    assert not (arrived & ids), (
        f"the repointed rule replayed events published before the change: "
        f"{sorted(arrived & ids)[:5]!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
