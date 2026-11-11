"""filter-log-events-json-selector-grammar."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "filter-log-events-json-selector-grammar"
GROUP = 'log-events'
SERVICES = ['logs']


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterLogEvents evaluates the JSON-selector filter-pattern grammar (field equality, nested
    paths, numeric comparisons, ``&&``) as a JSON predicate, not a substring scan: a plaintext event
    containing ``level=ERROR code=500`` must NOT match ``{$.level = "ERROR"}``.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-jsonfilter-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    # Four events with distinct "marker" values so a result set maps 1:1 to
    # the events that produced it. Three parse as JSON; the fourth is
    # deliberately plaintext but contains the same tokens.
    events = {
        "err-500-u1": json.dumps(
            {"level": "ERROR", "code": 500, "user": {"id": "u-1"}, "marker": "err-500-u1"}
        ),
        "info-200-u1": json.dumps(
            {"level": "INFO", "code": 200, "user": {"id": "u-1"}, "marker": "info-200-u1"}
        ),
        "err-503-u2": json.dumps(
            {"level": "ERROR", "code": 503, "user": {"id": "u-2"}, "marker": "err-503-u2"}
        ),
        "plaintext-decoy": 'marker=plaintext-decoy level=ERROR code=500 user.id="u-1" not-json',
    }
    base = _now_ms()
    ordered = list(events.items())
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base + i * 10, "message": msg} for i, (_m, msg) in enumerate(ordered)
        ],
    )

    def _all_markers():
        found = set()
        for ev in svc.filter_log_events(logGroupName=group).get("events", []):
            for marker in events:
                if marker in ev["message"]:
                    found.add(marker)
        return found

    _poll_until(
        _all_markers,
        lambda found: found == set(events),
        timeout_s=60,
        interval_s=2.0,
        description="all 4 seeded events become filterable",
    )

    def _markers_for(pattern):
        resp = svc.filter_log_events(logGroupName=group, filterPattern=pattern)
        found = set()
        for ev in resp.get("events", []):
            hits = [m for m in events if m in ev["message"]]
            assert hits, f"FilterLogEvents({pattern!r}) returned an event we never wrote: {ev!r}"
            found.update(hits)
        return found

    cases = [
        # (filterPattern, exact expected marker set, why this case exists)
        (
            '{$.level = "ERROR"}',
            {"err-500-u1", "err-503-u2"},
            "string equality on a top-level field; must NOT match the plaintext decoy",
        ),
        (
            "{$.code = 500}",
            {"err-500-u1"},
            "numeric equality (unquoted) selects exactly one event",
        ),
        (
            "{$.code > 400}",
            {"err-500-u1", "err-503-u2"},
            "numeric ordering comparison, not string comparison",
        ),
        (
            '{$.level = "ERROR" && $.user.id = "u-2"}',
            {"err-503-u2"},
            "&& conjunction over a top-level field and a NESTED path",
        ),
        (
            '{$.user.id = "u-1"}',
            {"err-500-u1", "info-200-u1"},
            "nested path equality on its own",
        ),
        (
            '{$.level = "WARN"}',
            set(),
            "a selector matching nothing returns an empty event list, not everything",
        ),
    ]

    failures = {}
    for pattern, expected, why in cases:
        got = _markers_for(pattern)
        if got != expected:
            failures[pattern] = f"expected {sorted(expected)}, got {sorted(got)} ({why})"

    assert not failures, (
        "FilterLogEvents JSON-selector grammar mismatches (a substring matcher fails "
        f"the first and last cases): {failures!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
