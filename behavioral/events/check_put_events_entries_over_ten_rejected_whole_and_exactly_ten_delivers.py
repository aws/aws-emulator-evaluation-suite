"""put-events-entries-over-ten-rejected-whole-and-exactly-ten-delivers."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-events-entries-over-ten-rejected-whole-and-exactly-ten-delivers"
GROUP = "put-events"
SERVICES = ["events"]

_MAX_ENTRIES = 10
_LIVENESS_TIMEOUT_S = 120.0
_DRAIN_TIMEOUT_S = 90.0
_DETAIL_TYPE = "sim2real-entry-count"


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _entry(bus: str, source: str, marker: str) -> dict:
    return {"EventBusName": bus, "Source": source, "DetailType": _DETAIL_TYPE, "Detail": json.dumps({"m": marker})}


def _rendered_entry(bus: str, source: str, marker: str) -> str:
    """The over-limit ValidationException echoes every rejected entry as a Java object dump;
    this renders one entry in that same form, from only the values the check sent."""
    detail = json.dumps({"m": marker})
    return (
        f"PutEventsRequestEntry(time=null, source={source}, resources=null, "
        f"detailType={_DETAIL_TYPE}, eventGroupId=null, detail={detail}, eventBusName={bus}, "
        f"traceHeader=null, kmsKeyIdentifier=null, internalMetadata=null)"
    )


def _too_many_entries_error(bus: str, source: str, markers: list[str]) -> tuple[str, str]:
    rendered = ", ".join(_rendered_entry(bus, source, m) for m in markers)
    return (
        "ValidationException",
        f"1 validation error detected: Value '[{rendered}]' at 'entries' failed to satisfy "
        f"constraint: Member must have length less than or equal to {_MAX_ENTRIES}",
    )


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """PutEvents accepts a request of exactly 10 entries and refuses one of 11 in full, with
    not one of the 11 reaching a rule's target.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutEvents.html
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    source = ctx.unique_name("sim2real.entrycount.")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    rule_arn = events.put_rule(
        Name=rule_name, EventBusName=bus, EventPattern=json.dumps({"source": [source]}),
        State="ENABLED",
    )["RuleArn"]

    def _delete_rule() -> None:
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=rule_name, EventBusName=bus)["Targets"]]
        if ids:
            events.remove_targets(Rule=rule_name, EventBusName=bus, Ids=ids)
        events.delete_rule(Name=rule_name, EventBusName=bus)

    ctx.on_cleanup(_delete_rule)

    queue_name = ctx.unique_name("sim2real-behav-q-")
    queue_url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    })})

    put = events.put_targets(Rule=rule_name, EventBusName=bus, Targets=[{"Id": "sim2real-q", "Arn": queue_arn}])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    # A just-registered target can drop the first few events before delivery is live.
    _wait_for_routing_live(ctx, events, sqs, bus, source, queue_url)

    # 11 entries, each with its own marker: the whole request must be refused, none delivered.
    over_markers = [ctx.unique_name(f"over-{i}-") for i in range(_MAX_ENTRIES + 1)]
    code, message = _error(
        lambda: events.put_events(Entries=[_entry(bus, source, m) for m in over_markers])
    )
    expected = _too_many_entries_error(bus, source, over_markers)
    assert (code, message) == expected, (
        f"a PutEvents request of {_MAX_ENTRIES + 1} entries must be refused with "
        f"{expected!r}, got {(code, message)!r}"
    )

    start = time.monotonic()
    seen = _drain(ctx, queue_url, until=lambda msgs: False, timeout_s=15.0, allow_empty=True)
    over_latency_s = max(time.monotonic() - start, 1.0)
    assert not any(json.loads(m["Body"])["detail"]["m"] in over_markers for m in seen), (
        "an entry from the refused 11-entry request reached the target"
    )

    # Exactly 10 entries, as the positive control, must succeed and every one must arrive.
    ok_markers = [ctx.unique_name(f"ok-{i}-") for i in range(_MAX_ENTRIES)]
    ok_start = time.monotonic()
    resp = events.put_events(Entries=[_entry(bus, source, m) for m in ok_markers])
    assert resp.get("FailedEntryCount", 0) == 0, f"a 10-entry request must be fully accepted, got {resp}"
    assert len(resp["Entries"]) == _MAX_ENTRIES, f"expected {_MAX_ENTRIES} results, got {resp['Entries']!r}"
    event_ids = [e.get("EventId") for e in resp["Entries"]]
    assert all(event_ids) and len(set(event_ids)) == _MAX_ENTRIES, (
        f"each of the {_MAX_ENTRIES} entries must get its own non-empty EventId, got {event_ids!r}"
    )

    arrived = _drain(
        ctx, queue_url,
        until=lambda msgs: {json.loads(m["Body"])["detail"]["m"] for m in msgs} >= set(ok_markers),
        timeout_s=_DRAIN_TIMEOUT_S,
    )
    ok_latency_s = time.monotonic() - ok_start
    arrived_markers = {json.loads(m["Body"])["detail"]["m"] for m in arrived}
    assert arrived_markers == set(ok_markers), (
        f"the 10 accepted entries must all arrive exactly once, got markers {sorted(arrived_markers)}"
    )

    # Hold a further window, sized off whichever leg is slower, to catch a target that
    # eventually (and wrongly) delivers an entry from the refused 11-entry request late.
    hold_s = max(15.0, 3.0 * max(over_latency_s, ok_latency_s))
    late = _drain(ctx, queue_url, until=lambda msgs: False, timeout_s=hold_s, allow_empty=True)
    assert not any(json.loads(m["Body"])["detail"]["m"] in over_markers for m in late), (
        f"an entry from the refused 11-entry request arrived late, within a {hold_s:.1f}s hold"
    )


def _drain(ctx, queue_url: str, *, until, timeout_s: float, allow_empty: bool = False) -> list[dict]:
    """Receive (and delete) until ``until(messages_so_far)`` holds; raise on timeout unless
    ``allow_empty`` permits ending the window with nothing new having arrived."""
    sqs = ctx.client("sqs")
    seen: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            seen.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if until(seen):
            return seen
    if allow_empty:
        return seen
    raise AssertionError(f"condition not met within {timeout_s}s; saw {len(seen)} message(s)")


def _wait_for_routing_live(ctx, events, sqs, bus: str, source: str, queue_url: str) -> None:
    """Re-publish a throwaway entry until it reaches the queue, proving the rule is routing
    before the graded entries are sent."""
    marker = ctx.unique_name("live-")
    deadline = time.monotonic() + _LIVENESS_TIMEOUT_S
    while time.monotonic() < deadline:
        events.put_events(Entries=[_entry(bus, source, marker)])
        window = time.monotonic() + 10.0
        while time.monotonic() < window:
            resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
            for msg in resp.get("Messages", []):
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                if json.loads(msg["Body"])["detail"]["m"] == marker:
                    return
    raise AssertionError(f"the rule never routed a liveness event within {_LIVENESS_TIMEOUT_S}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
