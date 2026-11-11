"""deep-cwlogs-semantics-filter-log-events-stream-prefix-scopes-and-merges-by-timestamp."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-cwlogs-semantics-filter-log-events-stream-prefix-scopes-and-merges-by-timestamp"
GROUP = "retrieval"
SERVICES = ["logs"]

# stream -> second offsets of its events. Streams share character prefixes on purpose:
# "web-" must select web-1/web-2 but NOT webhook-1; "web" must select all three.
_LAYOUT = {
    "web-1": [0, 20, 40],
    "web-2": [10, 30, 50],
    "webhook-1": [15, 35],
    "db-1": [5, 25],
}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterLogEvents with ``logStreamNamePrefix`` returns events of exactly the streams starting
    with that literal prefix, interleaved in timestamp order; a prefix matching no stream returns
    an empty result rather than an error."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-prefix-")
    logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    base = int(time.time() * 1000) - 120_000
    for stream, offsets in _LAYOUT.items():
        logs.create_log_stream(logGroupName=group, logStreamName=stream)
        logs.put_log_events(
            logGroupName=group,
            logStreamName=stream,
            logEvents=[{"timestamp": base + s * 1000, "message": f"{stream}@{s}"} for s in offsets],
        )

    def expected(prefix):
        rows = [(base + s * 1000, stream, f"{stream}@{s}")
                for stream, offs in _LAYOUT.items() if stream.startswith(prefix) for s in offs]
        return [(stream, msg) for _, stream, msg in sorted(rows)]

    window = (base - 60_000, base + 120_000)

    # Positive control: the unscoped query sees all four streams' events.
    everything = _poll_until(
        lambda: _filter_all(logs, group, window),
        lambda evs: len(evs) >= 10,
        timeout_s=90.0,
        description="FilterLogEvents to index all 10 events",
    )
    assert _rows(everything) == expected(""), (
        f"the unscoped query must return all 10 events in timestamp order; got {_rows(everything)!r}"
    )

    for prefix in ("web-", "web", "db-"):
        got = _rows(_filter_all(logs, group, window, logStreamNamePrefix=prefix))
        assert got == expected(prefix), (
            f"logStreamNamePrefix={prefix!r} must return exactly the events of streams starting "
            f"with {prefix!r}, merged in timestamp order: expected {expected(prefix)!r}, got {got!r}"
        )

    web_dash = _rows(_filter_all(logs, group, window, logStreamNamePrefix="web-"))
    assert not any(stream == "webhook-1" for stream, _ in web_dash), (
        f"'webhook-1' does not start with 'web-' yet its events came back: {web_dash!r}"
    )
    streams_in_order = [stream for stream, _ in web_dash]
    assert streams_in_order == ["web-1", "web-2"] * 3, (
        "events of web-1 and web-2 must interleave by timestamp, not concatenate per stream; "
        f"stream order was {streams_in_order!r}"
    )

    none = _filter_all(logs, group, window, logStreamNamePrefix="nomatch-")
    assert none == [], f"a prefix matching no stream must return no events, got {_rows(none)!r}"


def _rows(events):
    return [(e["logStreamName"], e["message"]) for e in events]


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last: {last!r}")


def _filter_all(logs, group, window, **extra):
    """Every page of FilterLogEvents (a page may be empty and still carry a nextToken)."""
    events, token = [], None
    for _ in range(200):
        kwargs = dict(logGroupName=group, startTime=window[0], endTime=window[1], **extra)
        if token:
            kwargs["nextToken"] = token
        resp = logs.filter_log_events(**kwargs)
        events.extend(resp.get("events", []))
        token = resp.get("nextToken")
        if not token:
            return events
    raise AssertionError("FilterLogEvents pagination did not terminate within 200 pages")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
