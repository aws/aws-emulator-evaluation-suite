"""put-events-one-mebibyte-request-limit-refused-whole-and-large-event-delivers-intact."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-events-one-mebibyte-request-limit-refused-whole-and-large-event-delivers-intact"
GROUP = "put-events"
SERVICES = ["events"]

_LIMIT = 1048576  # PutEvents: the entries of one request may total at most 1 MiB
_LEGACY_LIMIT = 262144  # the former 256 KiB event size limit
_LIVENESS_TIMEOUT_S = 120.0
_DELIVERY_TIMEOUT_S = 90.0
_OVER_LIMIT = "Total size of the entries in the request is over the limit."


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _entry(bus: str, source: str, detail_type: str, size: int, marker: str) -> dict:
    """An entry whose Source + DetailType + Detail weigh exactly ``size`` UTF-8 bytes."""
    shell = json.dumps({"m": marker, "pad": ""}, separators=(",", ":"))
    pad = size - len(source) - len(detail_type) - len(shell)
    assert pad >= 0, f"cannot build a {size}-byte entry around {shell!r}"
    detail = json.dumps({"m": marker, "pad": "z" * pad}, separators=(",", ":"))
    entry = {"EventBusName": bus, "Source": source, "DetailType": detail_type, "Detail": detail}
    weight = sum(len(entry[k].encode("utf-8")) for k in ("Source", "DetailType", "Detail"))
    assert weight == size, f"entry weighs {weight} bytes, intended {size}"
    return entry


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """PutEvents accepts exactly 1 MiB (Source + DetailType + Detail, UTF-8) and refuses a byte
    more, for one entry and for two sharing the limit, and a ~600 KB event reaches an SQS target
    intact.
    """
    events = ctx.client("events")

    bus = _create_bus(ctx, events)
    probe_source = ctx.unique_name("sim2real.size.")
    deliver_source = ctx.unique_name("sim2real.large.")
    rule_arn = _create_rule(ctx, events, bus, {"source": [deliver_source]})
    queue_url, queue_arn = _create_queue(ctx, MaximumMessageSize=str(_LIMIT))
    rule = rule_arn.rsplit("/", 1)[1]
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "sim2real-q", "Arn": queue_arn}])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    # The boundary, on a source no rule matches.
    at = events.put_events(Entries=[_entry(bus, probe_source, "size", _LIMIT, "at")])
    assert at["FailedEntryCount"] == 0 and at["Entries"][0].get("EventId"), (
        f"an entry of exactly {_LIMIT} bytes (1 MiB) must be accepted, got {at['Entries']!r}"
    )
    code, message = _error(
        lambda: events.put_events(Entries=[_entry(bus, probe_source, "size", _LIMIT + 1, "over")])
    )
    assert (code, message) == ("ValidationException", _OVER_LIMIT), (
        f"an entry of {_LIMIT + 1} bytes must be refused with ValidationException {_OVER_LIMIT!r}, "
        f"got {code!r}: {message!r}"
    )

    # The limit is the request's, not each entry's: two entries share it additively.
    half = 600000
    pair = events.put_events(Entries=[
        _entry(bus, probe_source, "size", half, "first"),
        _entry(bus, probe_source, "size", _LIMIT - half, "second"),
    ])
    assert pair["FailedEntryCount"] == 0 and len(pair["Entries"]) == 2, (
        f"two entries totalling exactly {_LIMIT} bytes must both be accepted, got {pair['Entries']!r}"
    )
    code, message = _error(lambda: events.put_events(Entries=[
        _entry(bus, probe_source, "size", half, "first"),
        _entry(bus, probe_source, "size", _LIMIT - half + 1, "second"),
    ]))
    assert (code, message) == ("ValidationException", _OVER_LIMIT), (
        f"two entries of {half} and {_LIMIT - half + 1} bytes each fit alone but exceed the request "
        f"limit together; the request must be refused whole with ValidationException "
        f"{_OVER_LIMIT!r}, got {code!r}: {message!r}"
    )

    # Liveness: a just-created rule can drop events until routing is live.
    marker = ctx.unique_name("live-")

    def _small_arrived(msgs: list[dict]) -> bool:
        return any(json.loads(m["Body"])["detail"].get("m") == marker for m in msgs)

    _publish_until_live(ctx, events, queue_url, {
        "EventBusName": bus, "Source": deliver_source, "DetailType": "live",
        "Detail": json.dumps({"m": marker}),
    }, _small_arrived)

    big_marker = ctx.unique_name("big-")
    big = _entry(bus, deliver_source, "large", 600000, big_marker)
    sent = events.put_events(Entries=[big])
    assert sent["FailedEntryCount"] == 0, f"the large event was refused: {sent['Entries']!r}"
    event_id = sent["Entries"][0]["EventId"]

    def _big_arrived(msgs: list[dict]) -> bool:
        return any(json.loads(m["Body"])["id"] == event_id for m in msgs)

    msgs = _drain(ctx, queue_url, until=_big_arrived, timeout_s=_DELIVERY_TIMEOUT_S,
                  description=f"the {len(big['Detail'])}-byte event {event_id} reaching the queue")
    envelope = next(json.loads(m["Body"]) for m in msgs if json.loads(m["Body"])["id"] == event_id)
    assert len(big["Detail"]) > _LEGACY_LIMIT, "the large event must exceed the old 256 KiB limit"
    assert envelope["detail"] == json.loads(big["Detail"]), (
        f"the large event's detail was not delivered intact: sent {len(big['Detail'])} bytes with "
        f"marker {big_marker!r}, received detail of {len(json.dumps(envelope['detail']))} bytes "
        f"with marker {envelope['detail'].get('m')!r}"
    )
    assert (envelope["source"], envelope["detail-type"]) == (deliver_source, "large"), (
        f"the large event arrived with source/detail-type {envelope['source']!r}/"
        f"{envelope['detail-type']!r}"
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
