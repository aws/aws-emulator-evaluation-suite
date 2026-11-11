"""put-log-events-empty-string-vs-absent-field-distinct."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-log-events-empty-string-vs-absent-field-distinct"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two JSON messages that differ only in an empty-string key versus an absent key come back from
    GetLogEvents as two distinct raw messages, byte for byte as written.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    stream_name = ctx.unique_name("sim2real-behav-ls-")

    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    message_with_empty_field = json.dumps({"marker": "distinct-probe", "value": ""})
    message_without_field = json.dumps({"marker": "distinct-probe"})
    assert message_with_empty_field != message_without_field, (
        f"test fixture bug: the two probe messages are identical: {message_with_empty_field!r}"
    )

    base_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[
            {"timestamp": base_ms, "message": message_with_empty_field},
            {"timestamp": base_ms + 1, "message": message_without_field},
        ],
    )

    events = _poll_for_events(ctx, group_name, stream_name, expected_count=2)
    messages = [e["message"] for e in events]
    assert message_with_empty_field in messages, (
        f"empty-string-field message missing/mangled: got {messages!r}"
    )
    assert message_without_field in messages, (
        f"absent-field message missing/mangled: got {messages!r}"
    )
    assert messages[0] != messages[1], (
        "the two distinct messages were coalesced into an identical value on read"
    )
    parsed = [json.loads(m) for m in messages]
    has_value_key = ["value" in p for p in parsed]
    assert True in has_value_key and False in has_value_key, (
        "expected exactly one retrieved message to retain the empty 'value' key "
        f"and one to omit it entirely; got presence flags {has_value_key!r}"
    )


def _poll_for_events(ctx, group_name, stream_name, expected_count=1, timeout_s=30.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    events = []
    while time.monotonic() < deadline:
        resp = logs.get_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            startFromHead=True,
        )
        events = resp.get("events", [])
        if len(events) >= expected_count:
            return events
        time.sleep(1.0)
    raise AssertionError(
        f"expected {expected_count} events, got {len(events)} within {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
