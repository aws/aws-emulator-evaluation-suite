"""put-events-request-size-accounting-is-additive-and-time-costs-fourteen-bytes."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Entry-size accounting: Time costs 14 bytes; Source, DetailType, Detail and each Resources entry
# cost their UTF-8 byte length (https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-putevents.html).
# The documented limit value differs between pages, so the wall is measured, never pinned.

CHECK = "put-events-request-size-accounting-is-additive-and-time-costs-fourteen-bytes"
GROUP = "event-propagation"
SERVICES = ["events", "sqs"]

_TIME_BYTES = 14  # documented cost of the Time parameter, in the entry-size accounting
_PROBE_CEILING = 1_200_000  # above both documented candidate limits (256KB and 1MB)
_SANITY_FLOOR = 100_000  # a measured limit below this is a target bug, not a doc ambiguity
_SANITY_CEILING = 1_100_000  # ... and above this it is not enforcing any documented limit
_NARROW_SLACK = 96  # bracket width for the three follow-up probes, in bytes
_LIVENESS_TIMEOUT_S = 120.0
_DELIVERY_TIMEOUT_S = 90.0
# '{"marker":"<32 hex>","pad":"' + pad + '"}' — the fixed overhead of the Detail JSON wrapper.
_DETAIL_OVERHEAD = len('{"marker":"') + 32 + len('","pad":"') + len('"}')


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """The PutEvents request-size limit is one number that Source, DetailType, Detail and each
    Resources entry all draw down additively, and supplying Time costs exactly 14 bytes of it."""
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    source_short = _xname(ctx, "s")
    source_long = source_short + ("z" * 200)
    resources = [
        f"arn:aws:events:{ctx.region}:{account}:event-bus/sim2real-probe-resource-one",
        f"arn:aws:events:{ctx.region}:{account}:event-bus/sim2real-probe-resource-two",
    ]

    # A bus with NO rules carries the bisection traffic, so ~48 large events are not delivered
    # anywhere. A second bus carries the one at-limit event whose delivery is asserted.
    probe_bus, _ = _create_bus(ctx)
    rule_bus, _ = _create_bus(ctx)

    queue = _create_queue(ctx)
    rule = _put_rule_with_projecting_target(ctx, rule_bus, {"source": [source_short]}, queue)

    # --- probe 1: the baseline wall, short Source, short DetailType, no Resources, no Time. ---
    base = _Shape(source=source_short, detail_type="SizeProbe", resources=None, with_time=False)
    d1 = _measure_wide(ctx, probe_bus, base)
    limit = base.overhead() + d1
    assert _SANITY_FLOOR <= limit <= _SANITY_CEILING, (
        f"the measured PutEvents request-size limit is {limit} bytes, outside the plausible range "
        f"[{_SANITY_FLOOR}, {_SANITY_CEILING}] that the two contradicting AWS docs bracket (256KB in "
        f"the API reference, 1MB in the user guide) — a target with no limit or a tiny one is what "
        f"this catches"
    )

    # --- probes 2-4: the same wall, reached through different fields. ---
    # DetailType has its own documented field-length cap of 128 characters (API_PutEventsRequestEntry),
    # a constraint independent of the entry-size-in-bytes budget this check measures. Padding it past
    # 128 trips that unrelated validation instead of the size wall, so the pad here stays well under it.
    long_names = _Shape(source=source_long, detail_type="SizeProbe" + ("y" * 100), resources=None, with_time=False)
    with_resources = _Shape(source=source_short, detail_type="SizeProbe", resources=resources, with_time=False)
    with_time = _Shape(source=source_short, detail_type="SizeProbe", resources=None, with_time=True)

    d2 = _measure_narrow(ctx, probe_bus, long_names, expected_total=limit)
    d3 = _measure_narrow(ctx, probe_bus, with_resources, expected_total=limit)
    d4 = _measure_narrow(ctx, probe_bus, with_time, expected_total=limit)

    measured = {
        "baseline": limit,
        "long source+detail-type": long_names.overhead() + d2,
        "with 2 resources": with_resources.overhead() + d3,
        "with Time": with_time.overhead() + d4,
    }
    assert len(set(measured.values())) == 1, (
        f"the request-size limit must be ONE number that every counted field draws down additively "
        f"per the documented accounting; the four probes measured {measured} — a target that limits "
        f"on the serialised request body, or that forgets to charge for Resources, disagrees here"
    )

    # --- the exact documented cost of Time, expressed as a difference between measurements. ---
    assert d1 - d4 == _TIME_BYTES, (
        f"supplying Time must cost exactly {_TIME_BYTES} bytes of the request budget: the largest "
        f"accepted Detail was {d1} bytes without Time and {d4} bytes with it, a difference of "
        f"{d1 - d4}. This is a fixed documented API constant, not an account quota"
    )

    # --- one byte over the wall is refused, the same way, for every shape. ---
    shapes = {"baseline": (base, d1), "long names": (long_names, d2), "resources": (with_resources, d3), "time": (with_time, d4)}
    refusals = {
        label: _reject_shape(ctx, probe_bus, shape, shape_detail_len + 1, label=label)
        for label, (shape, shape_detail_len) in shapes.items()
    }
    distinct = set(refusals.values())
    assert len(distinct) == 1, (
        f"one byte past the limit must be refused identically for every entry shape, got {refusals}"
    )
    surface, code, status, message = next(iter(distinct))
    assert status == 400, (
        f"an over-limit PutEvents must be a 400-class client error, got HTTPStatusCode={status!r} "
        f"with surface={surface!r} code={code!r}"
    )
    assert code, (
        f"the over-limit refusal must carry a non-empty error code; got surface={surface!r} "
        f"status={status!r}"
    )
    assert message == "Total size of the entries in the request is over the limit.", (
        f"the over-limit refusal must state the request-size limit; got {message!r} "
        f"(surface={surface!r} code={code!r})"
    )

    # --- the at-limit entry is not merely accepted, it is really delivered. ---
    # Liveness first: a freshly created rule silently drops events until routing goes live.
    _emit_until_delivered(ctx, rule_bus, base, _DETAIL_OVERHEAD, queue["url"])
    marker = uuid.uuid4().hex
    entry = base.entry(marker, d1)
    entry["EventBusName"] = rule_bus
    assert _entry_size(entry) == limit, (
        f"the at-limit entry must weigh exactly the measured limit {limit} by the documented "
        f"accounting, computed {_entry_size(entry)}"
    )
    resp = events.put_events(Entries=[entry])
    assert resp.get("FailedEntryCount") == 0 and (resp.get("Entries") or [{}])[0].get("EventId"), (
        f"the at-limit entry must be accepted with an EventId, got "
        f"{json.dumps(resp, default=str)[:300]}"
    )
    delivered = _await_projection(ctx, queue["url"], marker, timeout_s=_DELIVERY_TIMEOUT_S)
    assert delivered == {"m": marker}, (
        f"the at-limit event must be delivered through rule {rule['name']} and projected by the input "
        f"transformer to exactly the marker; the queue delivered {delivered!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


class _Shape:
    """One PutEvents entry shape: everything except the Detail length is fixed.

    `overhead()` is the documented entry-size contribution of every field OTHER than Detail, so
    `overhead() + len(Detail)` is the entry's documented size.
    """

    def __init__(self, *, source: str, detail_type: str, resources: list[str] | None, with_time: bool):
        self.source = source
        self.detail_type = detail_type
        self.resources = resources
        self.with_time = with_time

    def overhead(self) -> int:
        total = len(self.source.encode("utf-8")) + len(self.detail_type.encode("utf-8"))
        for resource in self.resources or []:
            total += len(resource.encode("utf-8"))
        if self.with_time:
            total += _TIME_BYTES
        return total

    def entry(self, marker: str, detail_len: int) -> dict[str, Any]:
        assert detail_len >= _DETAIL_OVERHEAD, (
            f"detail_len {detail_len} is below the JSON wrapper's own {_DETAIL_OVERHEAD} bytes"
        )
        detail = '{"marker":"' + marker + '","pad":"' + ("x" * (detail_len - _DETAIL_OVERHEAD)) + '"}'
        assert len(detail.encode("utf-8")) == detail_len, (
            f"detail construction is wrong: wanted {detail_len} bytes, built "
            f"{len(detail.encode('utf-8'))}"
        )
        entry: dict[str, Any] = {
            "Source": self.source,
            "DetailType": self.detail_type,
            "Detail": detail,
        }
        if self.resources:
            entry["Resources"] = list(self.resources)
        if self.with_time:
            entry["Time"] = datetime.now(timezone.utc)
        return entry


def _entry_size(entry: dict[str, Any]) -> int:
    """The documented PutEventsRequestEntry size for an already-built entry."""
    total = len(entry["Source"].encode("utf-8")) + len(entry["DetailType"].encode("utf-8"))
    total += len(entry["Detail"].encode("utf-8"))
    for resource in entry.get("Resources") or []:
        total += len(resource.encode("utf-8"))
    if entry.get("Time") is not None:
        total += _TIME_BYTES
    return total


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _tolerate(fn, *tolerated: str, leak: str = "") -> None:
    """Run a teardown call. With a leak label, an error code outside `tolerated` is reported as a
    leak; without one, a refused teardown call is ignored."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if leak and code not in tolerated:
            raise RuntimeError(f"{leak}: {code}") from exc


def _accepted(ctx, bus: str, shape: _Shape, detail_len: int) -> bool:
    """True iff PutEvents fully accepted a single entry of this shape and Detail length."""
    entry = shape.entry(uuid.uuid4().hex, detail_len)
    entry["EventBusName"] = bus
    try:
        resp = ctx.client("events").put_events(Entries=[entry])
    except ClientError:
        return False
    if resp.get("FailedEntryCount"):
        return False
    entries = resp.get("Entries") or []
    return len(entries) == 1 and bool(entries[0].get("EventId"))


def _reject_shape(ctx, bus: str, shape: _Shape, detail_len: int, *, label: str):
    """("exception"|"entry", code, http status, message) for an over-limit request; RAISES on
    acceptance."""
    entry = shape.entry(uuid.uuid4().hex, detail_len)
    entry["EventBusName"] = bus
    try:
        resp = ctx.client("events").put_events(Entries=[entry])
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = (exc.response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
        return ("exception", err.get("Code"), status, err.get("Message", ""))
    failed = resp.get("FailedEntries") or []
    if resp.get("FailedEntryCount") and failed:
        status = (resp.get("ResponseMetadata") or {}).get("HTTPStatusCode")
        return ("entry", failed[0].get("ErrorCode"), status, failed[0].get("ErrorMessage", ""))
    raise AssertionError(
        f"PutEvents ACCEPTED a request one byte past the measured limit ({label}, entry size "
        f"{shape.overhead() + detail_len}) — the limit is not being enforced consistently. Response "
        f"was {json.dumps(resp, default=str)[:300]}"
    )


def _measure_wide(ctx, bus: str, shape: _Shape) -> int:
    """The greatest accepted Detail length for `shape`, bisected over the full plausible range.

    Both ends are established by measurement before the search starts, so a target that refuses
    everything and a target that accepts everything both fail here rather than silently returning an
    endpoint of the interval.
    """
    low = _DETAIL_OVERHEAD
    high = _PROBE_CEILING
    assert _accepted(ctx, bus, shape, low), (
        f"positive control failed: a minimal {low}-byte Detail must be accepted on bus {bus}; if it "
        f"is not, every 'refused' verdict in the bisection is meaningless"
    )
    assert not _accepted(ctx, bus, shape, high), (
        f"a Detail of {high} bytes was ACCEPTED — that is past both documented candidate limits "
        f"(256KB and 1MB), so the target is enforcing no request-size limit at all"
    )
    return _bisect(ctx, bus, shape, low, high)


def _measure_narrow(ctx, bus: str, shape: _Shape, *, expected_total: int) -> int:
    """The greatest accepted Detail length for `shape`, bisected in a small bracket around the
    baseline's measured limit. Cheap, because it avoids re-uploading the full ladder.

    If the bracket turns out not to contain the wall, both bracket assertions below fail loudly with
    the numbers — which is itself the disagreement this check exists to detect.
    """
    centre = expected_total - shape.overhead()
    low = max(_DETAIL_OVERHEAD, centre - _NARROW_SLACK)
    high = centre + _NARROW_SLACK
    assert _accepted(ctx, bus, shape, low), (
        f"the bracket for this shape does not start below the wall: a Detail of {low} bytes "
        f"(entry size {shape.overhead() + low}) was refused, while the baseline measured a limit of "
        f"{expected_total}. That disagreement IS the finding — the accounting is not additive"
    )
    assert not _accepted(ctx, bus, shape, high), (
        f"the bracket for this shape does not end above the wall: a Detail of {high} bytes "
        f"(entry size {shape.overhead() + high}) was accepted, while the baseline measured a limit of "
        f"{expected_total}. That disagreement IS the finding — the accounting is not additive"
    )
    return _bisect(ctx, bus, shape, low, high)


def _bisect(ctx, bus: str, shape: _Shape, low: int, high: int) -> int:
    """Bisect a bracket whose low end is known accepted and high end known refused.

    Re-probes the answer once, so a non-monotonic target fails loudly instead of being mis-measured.
    """
    while high - low > 1:
        mid = (low + high) // 2
        if _accepted(ctx, bus, shape, mid):
            low = mid
        else:
            high = mid
    assert _accepted(ctx, bus, shape, low), (
        f"bisection inconsistency: Detail length {low} was accepted during the search and is refused "
        f"on re-probe, so the request-size limit is not stable"
    )
    return low


def _create_bus(ctx) -> tuple[str, str]:
    events = ctx.client("events")
    name = _xname(ctx, "bus")
    arn = events.create_event_bus(Name=name, Tags=_xsvc_tags_kv())["EventBusArn"]

    def _teardown(n=name):
        _tolerate(lambda: ctx.client("events").delete_event_bus(Name=n), "ResourceNotFoundException", leak=f"could not delete event bus {n}")

    ctx.on_cleanup(_teardown)
    return name, arn


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = _xname(ctx, "q")
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _put_rule_with_projecting_target(ctx, bus: str, pattern: dict, queue: dict) -> dict[str, str]:
    """A rule whose SQS target carries an InputTransformer projecting only $.detail.marker."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")
    arn = events.put_rule(
        Name=name, EventBusName=bus, EventPattern=json.dumps(pattern), Tags=_xsvc_tags_kv()
    )["RuleArn"]

    def _teardown(n=name, b=bus):
        ev = ctx.client("events")
        _tolerate(lambda: ev.remove_targets(Rule=n, EventBusName=b, Ids=["t1"]), "ResourceNotFoundException", leak=f"could not remove target t1 from rule {n}")
        _tolerate(lambda: ev.delete_rule(Name=n, EventBusName=b, Force=True), "ResourceNotFoundException", leak=f"could not delete rule {n} on bus {b}")

    ctx.on_cleanup(_teardown)
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowEventsSend",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue["arn"],
                            "Condition": {"ArnEquals": {"aws:SourceArn": arn}},
                        }
                    ],
                }
            )
        },
    )
    events.put_targets(
        Rule=name,
        EventBusName=bus,
        Targets=[
            {
                "Id": "t1",
                "Arn": queue["arn"],
                "InputTransformer": {
                    "InputPathsMap": {"m": "$.detail.marker"},
                    "InputTemplate": '{"m": "<m>"}',
                },
            }
        ],
    )
    return {"name": name, "arn": arn}


def _body(msg: dict):
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _drain(ctx, queue_url: str, *, window_s: float, max_total: int = 25) -> list:
    sqs = ctx.client("sqs")
    seen: list = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            seen.append(_body(msg))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _await_projection(ctx, queue_url: str, marker: str, *, timeout_s: float) -> dict:
    """Poll until the projected message for `marker` arrives. RAISES on timeout."""
    strangers: list = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for body in _drain(ctx, queue_url, window_s=min(8.0, max(1.0, deadline - time.monotonic()))):
            if isinstance(body, dict) and body.get("m") == marker:
                return body
            strangers.append(body)
    raise AssertionError(
        f"the projected message for marker {marker!r} never arrived on {queue_url} within "
        f"{timeout_s}s (other bodies seen: {json.dumps(strangers, default=str)[:200]})"
    )


def _emit_until_delivered(ctx, bus: str, shape: _Shape, detail_len: int, queue_url: str) -> None:
    """Emit small events with fresh markers until one is delivered, proving the rule is live.

    Re-emitting is required rather than optional: a freshly created rule silently drops events until
    the routing goes live, and EventBridge never retries a dropped event. Without this the at-limit
    delivery assertion below could fail for a reason that has nothing to do with size.
    """
    events = ctx.client("events")
    deadline = time.monotonic() + _LIVENESS_TIMEOUT_S
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        marker = uuid.uuid4().hex
        entry = shape.entry(marker, detail_len)
        entry["EventBusName"] = bus
        resp = events.put_events(Entries=[entry])
        assert resp.get("FailedEntryCount") == 0, (
            f"PutEvents on bus {bus} must be accepted while establishing liveness, got {resp!r}"
        )
        for body in _drain(ctx, queue_url, window_s=8.0):
            if isinstance(body, dict) and body.get("m") == marker:
                return
    raise AssertionError(
        f"no small control event reached {queue_url} from bus {bus} after {attempts} PutEvents "
        f"attempts over {_LIVENESS_TIMEOUT_S}s — the rule never went live, so the at-limit delivery "
        f"assertion could not be attempted"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
