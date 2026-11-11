"""put-events-detail-json-nesting-depth-limit."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "put-events-detail-json-nesting-depth-limit"
GROUP = "put-events"
SERVICES = ["events"]

_DOC_DEPTH = 1000  # documented in the PutEvents API reference
# Bisection ceiling: well above the documented limit; at ~6 bytes per level the probe stays far
# below the request-size limit, so a refusal is for depth, not size.
_CEILING = 4096
_SOURCE = "sim2real.nesting"


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """The deepest Detail PutEvents accepts is the same for nested objects, arrays and a mixed
    chain, is the documented 1000 levels (within one), and one level deeper is refused identically.

    Reference: https://docs.aws.amazon.com/cli/latest/reference/events/put-events.html
    """
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=_tags_kv())
    ctx.on_cleanup(lambda n=bus: _delete_bus_quietly(ctx, n))

    shapes = {"objects": _objects, "arrays": _arrays, "mixed": _mixed}
    measured: dict[str, int] = {}
    reject_shapes: dict[str, tuple] = {}

    for label, build in shapes.items():
        # Positive control per shape: without it the bisection could measure broken wiring.
        assert _accepted(events, bus, build(1)), (
            f"positive control failed: a depth-1 {label} Detail must be accepted by PutEvents on "
            f"bus {bus}; if this fails, every 'rejected' verdict below is meaningless"
        )
        assert not _accepted(events, bus, build(_CEILING)), (
            f"a {label} Detail nested {_CEILING} levels deep was ACCEPTED — real EventBridge "
            f"documents a {_DOC_DEPTH}-level limit (H1), so a target with no depth limit at all is "
            f"what this measures"
        )
        depth = _max_accepted_depth(events, bus, build)
        measured[label] = depth
        # Confirm the bisection landed on a real edge rather than on a non-monotonic patch.
        assert _accepted(events, bus, build(depth)), (
            f"bisection inconsistency for {label}: depth {depth} was accepted during the search but "
            f"is refused on re-probe — the limit is not stable"
        )
        reject_shapes[label] = _reject_shape(events, bus, build(depth + 1), label=f"{label}@{depth + 1}")

    # The limit is a property of depth, not container kind; a parser's object-only guard differs.
    assert len(set(measured.values())) == 1, (
        f"the nesting-depth limit must be a property of depth, not of container kind: measured "
        f"maximum accepted depth per shape was {measured} — a target whose limit differs between "
        f"nested objects, nested arrays and an alternating chain is applying its parser's guard, "
        f"not EventBridge's (H3)"
    )
    depth = measured["objects"]

    # +-1 because the docs do not say whether the outermost container counts.
    assert _DOC_DEPTH - 1 <= depth <= _DOC_DEPTH + 1, (
        f"the maximum accepted nesting depth must be the documented {_DOC_DEPTH} levels (±1 for the "
        f"undocumented question of whether the outermost container counts); measured {depth} "
        f"across shapes {measured} (H2)"
    )

    # A too-deep Detail may be a request-level ClientError or a per-entry ErrorCode; neither is
    # documented, so the check only requires all three shapes to be refused the same way.
    distinct = set(reject_shapes.values())
    assert len(distinct) == 1, (
        f"one level past the limit must be refused identically for every container shape, got "
        f"{reject_shapes} (H4)"
    )
    surface, code, message = next(iter(distinct))
    assert code, (
        f"the too-deep refusal must carry a non-empty error code; got surface={surface!r} "
        f"code={code!r} message={message!r} (H4)"
    )


_MANAGED_TAG_KEY = "sim2real:managed"


def _tags_kv() -> list[dict[str, str]]:
    return [
        {"Key": _MANAGED_TAG_KEY, "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]


def _objects(depth: int) -> str:
    """`depth` nested JSON objects. Built as text, never via json.dumps, so this process's own
    recursion limit is not what is being measured."""
    return '{"a":' * depth + "null" + "}" * depth


def _arrays(depth: int) -> str:
    """One object wrapper plus depth-1 nested arrays: the same total container count as _objects."""
    inner = "[" * (depth - 1) + "null" + "]" * (depth - 1) if depth > 1 else "null"
    return '{"a":' + inner + "}"


def _mixed(depth: int) -> str:
    """An alternating object/array chain of exactly `depth` containers, outermost an object."""
    opens, closes = [], []
    for level in range(depth):
        if level % 2 == 0:
            opens.append('{"a":')
            closes.append("}")
        else:
            opens.append("[")
            closes.append("]")
    return "".join(opens) + "null" + "".join(reversed(closes))


def _accepted(events, bus: str, detail: str) -> bool:
    """True iff PutEvents fully accepted the entry: no ClientError, no failed entry, an EventId back.

    A 200 with no EventId is not an acceptance.
    """
    try:
        resp = events.put_events(
            Entries=[
                {
                    "Source": _SOURCE,
                    "DetailType": "NestingProbe",
                    "Detail": detail,
                    "EventBusName": bus,
                }
            ]
        )
    except ClientError:
        return False
    if resp.get("FailedEntryCount"):
        return False
    entries = resp.get("Entries") or []
    return len(entries) == 1 and bool(entries[0].get("EventId"))


def _reject_shape(events, bus: str, detail: str, *, label: str):
    """("exception"|"entry", code, message) for a Detail expected to be refused; RAISES on acceptance.

    Raising, rather than returning a falsy sentinel, keeps an acceptance from passing as a mismatch.
    """
    try:
        resp = events.put_events(
            Entries=[
                {
                    "Source": _SOURCE,
                    "DetailType": "NestingProbe",
                    "Detail": detail,
                    "EventBusName": bus,
                }
            ]
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return ("exception", err.get("Code"), err.get("Message") or "")
    entries = resp.get("Entries") or []
    if resp.get("FailedEntryCount") and entries and not entries[0].get("EventId"):
        return ("entry", entries[0].get("ErrorCode"), entries[0].get("ErrorMessage") or "")
    raise AssertionError(
        f"PutEvents ACCEPTED the over-deep Detail probe {label} — expected a refusal one level past "
        f"the measured maximum. Response was {json.dumps(resp, default=str)[:300]}"
    )


def _max_accepted_depth(events, bus: str, build) -> int:
    """Bisect [1, _CEILING] for the greatest depth PutEvents accepts.

    The caller has already proved depth 1 is accepted and depth _CEILING is refused, so the interval
    is bracketed on both sides before the search starts and the loop is bounded by log2(_CEILING).
    """
    low, high = 1, _CEILING  # accepted, refused
    while high - low > 1:
        mid = (low + high) // 2
        if _accepted(events, bus, build(mid)):
            low = mid
        else:
            high = mid
    return low


def _delete_bus_quietly(ctx, name: str) -> None:
    try:
        ctx.client("events").delete_event_bus(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise RuntimeError(f"could not delete event bus {name}: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
