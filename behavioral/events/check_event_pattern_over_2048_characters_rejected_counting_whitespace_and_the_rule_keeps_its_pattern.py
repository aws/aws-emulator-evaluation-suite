"""event-pattern-over-2048-characters-rejected-counting-whitespace-and-the-rule-keeps-its-pattern."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-pattern-over-2048-characters-rejected-counting-whitespace-and-the-rule-keeps-its-pattern"
GROUP = "rule-limits"
SERVICES = ["events"]

_LIMIT = 2048


@tags("plane:control", "axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation")
def run(ctx) -> None:
    """PutRule accepts a 2048-character pattern and refuses 2049, counting the text as sent
    (a pretty-printed pattern whose compact form fits is refused); refusals keep the stored pattern.
    """
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    rule = ctx.unique_name("sim2real-behav-rule-")
    events.put_rule(Name=rule, EventBusName=bus, EventPattern=json.dumps({"source": ["sim2real.limit"]}))
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, EventBusName=bus))

    def _sized(n: int) -> tuple[str, str]:
        value = "y" * (n - len('{"source":[""]}'))
        text = json.dumps({"source": [value]}, separators=(",", ":"))
        assert len(text) == n
        return text, value

    at_limit, value = _sized(_LIMIT)
    events.put_rule(Name=rule, EventBusName=bus, EventPattern=at_limit)
    stored = events.describe_rule(Name=rule, EventBusName=bus)["EventPattern"]
    assert stored == at_limit, f"a {_LIMIT}-character pattern was stored as {len(stored)} characters"

    refusal = ("InvalidEventPatternException",
               f"Parameter EventPattern for rule {rule} exceeds limit of {_LIMIT}.")
    over, _ = _sized(_LIMIT + 1)
    got = _error(lambda: events.put_rule(Name=rule, EventBusName=bus, EventPattern=over))
    assert got == refusal, f"a {_LIMIT + 1}-character pattern gave {got!r}"
    _assert_kept(ctx, events, rule, bus, at_limit, value)

    # The whitespace case separates measuring the request text from a re-serialised pattern.
    sources = [f"sim2real.s{i:03d}" for i in range(120)]
    compact = json.dumps({"source": sources}, separators=(",", ":"))
    pretty = json.dumps({"source": sources}, indent=2)
    assert len(compact) < _LIMIT < len(pretty), (len(compact), len(pretty))
    got = _error(lambda: events.put_rule(Name=rule, EventBusName=bus, EventPattern=pretty))
    assert got == refusal, (
        f"a pattern of {len(pretty)} characters as sent ({len(compact)} compact) gave {got!r}"
    )
    _assert_kept(ctx, events, rule, bus, at_limit, value)

    events.put_rule(Name=rule, EventBusName=bus, EventPattern=compact)
    assert events.describe_rule(Name=rule, EventBusName=bus)["EventPattern"] == compact, (
        "the compact form of the refused pattern was not accepted and stored verbatim"
    )


def _assert_kept(ctx, events, rule: str, bus: str, pattern: str, value: str) -> None:
    stored = events.describe_rule(Name=rule, EventBusName=bus)["EventPattern"]
    assert stored == pattern, (
        f"a refused update changed the stored pattern ({len(stored)} characters, expected {len(pattern)})"
    )
    event = json.dumps({"id": "1", "account": ctx.account, "source": value, "time": "2026-01-01T00:00:00Z",
                        "region": ctx.region, "resources": [], "detail-type": "t", "detail": {}})
    assert events.test_event_pattern(EventPattern=stored, Event=event)["Result"] is True, (
        "the kept pattern no longer matches the event it was written for"
    )


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call succeeded; real AWS refuses it")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
