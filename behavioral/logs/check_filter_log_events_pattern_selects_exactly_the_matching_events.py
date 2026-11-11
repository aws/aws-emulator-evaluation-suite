"""filter-log-events-pattern-selects-exactly-the-matching-events."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "filter-log-events-pattern-selects-exactly-the-matching-events"
GROUP = 'log-events'
SERVICES = ['logs']

_JSON_ERROR = json.dumps({"level": "ERROR", "msg": "sim2real-json-error"})
_JSON_INFO = json.dumps({"level": "INFO", "msg": "sim2real-json-info"})
_UPPER_TIMEOUT = "sim2real plain Timeout upstream"
_EMBEDDED_TIMEOUT = "sim2real plain RequestTimeoutError upstream"
_LOWER_TIMEOUT = "sim2real plain timeout upstream"
_OTHER_A = "sim2real unrelated alpha"
_OTHER_B = "sim2real unrelated beta"

_ALL = [
    _JSON_ERROR,
    _JSON_INFO,
    _UPPER_TIMEOUT,
    _EMBEDDED_TIMEOUT,
    _LOWER_TIMEOUT,
    _OTHER_A,
    _OTHER_B,
]

_NO_MATCH_PATTERN = '"sim2real-token-that-appears-in-no-event"'


# ===== helpers =====
def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """filterPattern selects EXACTLY the intended events: a JSON selector matches a field and ignores
    non-JSON events, a quoted term is case-sensitive and matches inside a longer word, and a pattern
    that matches nothing returns the empty set; each leg is an exact set equality.
    """
    svc = ctx.client("logs")

    group = ctx.unique_name("sim2real-behav-lg-filterpat-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    base = _now_ms() - len(_ALL) * 100
    resp = svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base + i * 100, "message": msg} for i, msg in enumerate(_ALL)
        ],
    )
    assert "rejectedLogEventsInfo" not in resp, (
        f"the fixture batch was partially rejected, so the per-pattern comparisons below would be "
        f"against an incomplete event set: {resp!r}"
    )

    def _filter(pattern=None):
        """Every page, so leftovers in a shared account cannot truncate the answer."""
        messages: list[str] = []
        token = None
        while True:
            kwargs = {"logGroupName": group}
            if pattern is not None:
                kwargs["filterPattern"] = pattern
            if token is not None:
                kwargs["nextToken"] = token
            page = svc.filter_log_events(**kwargs)
            messages.extend(e["message"] for e in page.get("events", []))
            token = page.get("nextToken")
            if not token:
                break
        return messages

    # Separate ingestion latency from filtering: the UNFILTERED read must see all of
    # them before any pattern is judged.
    all_msgs = _poll_until(
        lambda: _filter(),
        lambda msgs: len(msgs) >= len(_ALL),
        timeout_s=150,
        interval_s=3.0,
        description=f"the unfiltered read sees all {len(_ALL)} written events",
    )
    assert len(all_msgs) == len(_ALL), (
        f"the unfiltered read returned {len(all_msgs)!r} events, expected {len(_ALL)!r}, so the "
        f"per-pattern comparisons would be against an incomplete event set: {all_msgs!r}"
    )
    assert set(all_msgs) == set(_ALL), (
        f"the unfiltered read returned {sorted(all_msgs)!r}, expected exactly {sorted(_ALL)!r}"
    )

    # --- 1. A JSON selector matches on the field value, and silently ignores the
    # five events that are not JSON at all.
    json_error_msgs = _filter('{$.level = "ERROR"}')
    assert set(json_error_msgs) == {_JSON_ERROR}, (
        'the pattern {$.level = "ERROR"} returned '
        f"{sorted(json_error_msgs)!r}, expected exactly the one ERROR event "
        f"{_JSON_ERROR!r} -- the INFO event carries the same field with a different value and the "
        "five plain-text events are not JSON at all"
    )

    # --- 2. A quoted term is case-sensitive and matches a substring inside a longer
    # word: 'Timeout' selects the standalone occurrence AND the one embedded in
    # RequestTimeoutError, but not the lower-case one.
    quoted_msgs = _filter('"Timeout"')
    assert set(quoted_msgs) == {_UPPER_TIMEOUT, _EMBEDDED_TIMEOUT}, (
        'the quoted pattern "Timeout" must be case-sensitive and substring-matching, so it selects '
        f"{sorted([_UPPER_TIMEOUT, _EMBEDDED_TIMEOUT])!r} and must NOT select {_LOWER_TIMEOUT!r}; "
        f"got {sorted(quoted_msgs)!r}"
    )

    # --- 3. A pattern matching nothing returns the EMPTY set. An emulator that
    # ignores the pattern returns all seven here.
    no_match_msgs = _filter(_NO_MATCH_PATTERN)
    assert no_match_msgs == [], (
        f"a pattern matching nothing must return the empty set, got {no_match_msgs!r} -- a filter "
        "that ignores the pattern returns everything"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
