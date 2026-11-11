"""put-events-trace-header-reaches-sqs-targets-as-aws-trace-header."""
from __future__ import annotations

import json
import secrets
import time

from behavioral_harness import tags

CHECK = "put-events-trace-header-reaches-sqs-targets-as-aws-trace-header"
GROUP = "put-events"
SERVICES = ["events"]

_LIVENESS_TIMEOUT_S = 120.0
_DELIVERY_TIMEOUT_S = 90.0


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A well-formed X-Ray TraceHeader on a PutEvents entry reaches raw and input-transformed SQS
    targets as the AWSTraceHeader attribute; entries without one, or with a malformed one, arrive
    without it. A malformed header is still accepted by PutEvents.
    """
    events = ctx.client("events")

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.trace.")
    rule_arn = _create_rule(ctx, events, bus, {"source": [source]})
    rule = rule_arn.rsplit("/", 1)[1]
    queue_url, queue_arn = _create_queue(ctx)
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": "raw", "Arn": queue_arn},
        {"Id": "shaped", "Arn": queue_arn, "InputTransformer": {
            "InputPathsMap": {"m": "$.detail.m", "id": "$.id"},
            "InputTemplate": '{"shaped": <m>, "id": <id>}',
        }},
    ])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    live = ctx.unique_name("live-")
    _publish_until_live(ctx, events, queue_url, {
        "EventBusName": bus, "Source": source, "DetailType": "live",
        "Detail": json.dumps({"m": live}),
    }, lambda msgs: any(live in m["Body"] for m in msgs))

    trace = (
        f"Root=1-{int(time.time()):08x}-{secrets.token_hex(12)};"
        f"Parent={secrets.token_hex(8)};Sampled=1"
    )
    markers = {k: ctx.unique_name(f"{k}-") for k in ("traced", "plain", "malformed")}
    headers = {"traced": trace, "malformed": "sim2real-not-a-trace-header"}
    entries = []
    for kind, marker in markers.items():
        entry = {"EventBusName": bus, "Source": source, "DetailType": "trace",
                 "Detail": json.dumps({"m": marker})}
        if kind in headers:
            entry["TraceHeader"] = headers[kind]
        entries.append(entry)
    # One request for all three, so a missing header on the untraced deliveries is not lag.
    resp = events.put_events(Entries=entries)
    assert resp["FailedEntryCount"] == 0 and all(e.get("EventId") for e in resp["Entries"]), (
        f"PutEvents must accept all three entries, the malformed trace header included: "
        f"{resp['Entries']!r}"
    )
    ids = {kind: e["EventId"] for kind, e in zip(markers, resp["Entries"])}

    def _label(msg: dict) -> tuple[str, str] | None:
        body = json.loads(msg["Body"])
        if "shaped" in body:
            m, form = body["shaped"], "shaped"
        else:
            m, form = body.get("detail", {}).get("m"), "raw"
        kind = next((k for k, v in markers.items() if v == m), None)
        return (kind, form) if kind else None

    def _complete(msgs: list[dict]) -> bool:
        return {_label(m) for m in msgs} >= {(k, f) for k in markers for f in ("raw", "shaped")}

    msgs = _drain(ctx, queue_url, until=_complete, timeout_s=_DELIVERY_TIMEOUT_S,
                  description="all three events reaching both targets")
    seen: dict[tuple[str, str], set] = {}
    for msg in msgs:
        label = _label(msg)
        if label is None:
            continue
        body = json.loads(msg["Body"])
        assert body["id"] == ids[label[0]], (
            f"the {label} delivery carries event id {body['id']!r}, not the EventId PutEvents "
            f"returned for that entry ({ids[label[0]]!r})"
        )
        seen.setdefault(label, set()).add(msg.get("Attributes", {}).get("AWSTraceHeader"))

    for form in ("raw", "shaped"):
        assert seen[("traced", form)] == {trace}, (
            f"the {form} target's copy of the traced event must carry AWSTraceHeader {trace!r}, "
            f"got {sorted(map(str, seen[('traced', form)]))!r}"
        )
        assert seen[("plain", form)] == {None}, (
            f"the {form} target's copy of the event sent without a TraceHeader carries "
            f"AWSTraceHeader {sorted(map(str, seen[('plain', form)]))!r}"
        )
        assert seen[("malformed", form)] == {None}, (
            f"the {form} target's copy of the event with a malformed TraceHeader must arrive "
            f"without AWSTraceHeader, got {sorted(map(str, seen[('malformed', form)]))!r}"
        )



def _create_bus(ctx, events) -> str:
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    return bus


def _create_rule(ctx, events, bus: str, pattern: dict) -> str:
    """A rule whose teardown first removes whatever targets it still carries."""
    name = ctx.unique_name("sim2real-behav-rule-")
    arn = events.put_rule(
        Name=name, EventBusName=bus, EventPattern=json.dumps(pattern), State="ENABLED"
    )["RuleArn"]

    def _delete() -> None:
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=name, EventBusName=bus)["Targets"]]
        if ids:
            events.remove_targets(Rule=name, EventBusName=bus, Ids=ids)
        events.delete_rule(Name=name, EventBusName=bus)

    ctx.on_cleanup(_delete)
    return arn


def _create_queue(ctx, **attributes: str) -> tuple[str, str]:
    """A queue EventBridge may send to, as (url, arn)."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-q-")
    url = sqs.create_queue(QueueName=name, Attributes=attributes, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _drain(ctx, queue_url: str, *, until, timeout_s: float, description: str) -> list[dict]:
    """Receive (and delete) until ``until(messages_so_far)`` holds; raise on timeout."""
    sqs = ctx.client("sqs")
    seen: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
            AttributeNames=["All"], MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            seen.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if until(seen):
            return seen
    raise AssertionError(
        f"{description}: not met within {timeout_s}s; received {len(seen)} message(s): "
        f"{[m['Body'][:300] for m in seen]!r}"
    )


def _publish_until_live(ctx, events, queue_url: str, entry: dict, arrived) -> None:
    """Re-publish ``entry`` until the queue shows it: a just-created rule can drop events until
    its routing is live. Bounded; raises naming the timeout."""
    sqs = ctx.client("sqs")
    seen: list[dict] = []
    deadline = time.monotonic() + _LIVENESS_TIMEOUT_S
    while time.monotonic() < deadline:
        events.put_events(Entries=[entry])
        window = time.monotonic() + 15.0
        while time.monotonic() < window:
            resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
            for msg in resp.get("Messages", []):
                seen.append(msg)
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if arrived(seen):
                return
    raise AssertionError(
        f"the rule never delivered a liveness event within {_LIVENESS_TIMEOUT_S}s; "
        f"{len(seen)} other message(s) seen"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
