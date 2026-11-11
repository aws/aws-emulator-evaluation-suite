"""deep-cwlogs-semantics-filter-log-events-and-metric-filter-agree-on-pattern-verdicts."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "deep-cwlogs-semantics-filter-log-events-and-metric-filter-agree-on-pattern-verdicts"
GROUP = "pattern-agreement"
SERVICES = ["cloudwatch", "logs"]

_LINES = [
    "ERROR disk full on /dev/sda1",
    "error lowercase should not match a case-sensitive term",
    "WARN connection timeout after 30s",
    "ERROR request timeout upstream",
    "INFO all good",
    '{"level": "error", "code": 503, "msg": "unavailable"}',
    '{"level": "error", "code": 404, "msg": "missing"}',
    '{"level": "info", "code": 200, "msg": "ok"}',
    "127.0.0.1 GET /index.html 404 512",
    "10.0.0.2 POST /api 200 128",
    "10.0.0.3 GET /missing 404 0",
]

# pattern key -> (filter pattern, 0-based indices into _LINES that AWS matches). The indices are
# asserted as well as the agreement, so evaluators that agree on a WRONG verdict still fail.
_PATTERNS = {
    "Term": ("ERROR", [0, 3]),
    "Either": ("?ERROR ?WARN", [0, 2, 3]),
    "Exclude": ("ERROR -timeout", [0]),
    "Json": ('{ ($.level = "error") && ($.code >= 500) }', [5]),
    "Spaced": ("[ip, verb, path, status = 404, size]", [8, 10]),
    "Phrase": ('"disk full"', [0]),
}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """For six filter-pattern grammars over the same eleven events, TestMetricFilter, FilterLogEvents and
    a live metric filter (Sum per pattern) all select exactly the lines AWS matches.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    group = ctx.unique_name("sim2real-behav-lg-agree-")
    namespace = ctx.unique_name("sim2real-behav-agree-ns-")
    logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream = "events"
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    for key, (pattern, _) in _PATTERNS.items():
        name = f"agree-{key}"
        logs.put_metric_filter(
            logGroupName=group,
            filterName=name,
            filterPattern=pattern,
            metricTransformations=[
                {"metricName": key, "metricNamespace": namespace, "metricValue": "1"}
            ],
        )
        ctx.on_cleanup(lambda _n=name: logs.delete_metric_filter(logGroupName=group, filterName=_n))

    # Evaluator 1: TestMetricFilter (eventNumber is 1-based).
    for key, (pattern, expected) in _PATTERNS.items():
        matches = logs.test_metric_filter(filterPattern=pattern, logEventMessages=_LINES)["matches"]
        got = sorted(m["eventNumber"] - 1 for m in matches)
        assert got == expected, (
            f"TestMetricFilter({pattern!r}) matched line indices {got!r}; real AWS matches "
            f"{expected!r} ({[_LINES[i] for i in expected]!r})"
        )

    base = int(time.time() * 1000) - 5000
    resp = logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": base + i, "message": m} for i, m in enumerate(_LINES)],
    )
    assert "rejectedLogEventsInfo" not in resp, f"the fixture batch was partially rejected: {resp!r}"
    window = dict(startTime=base - 60_000, endTime=base + 60_000)

    # Evaluator 2: FilterLogEvents over the stored events. First wait for the unfiltered
    # query to see all eleven, so an empty filtered result cannot be indexing lag.
    _poll_until(
        lambda: _filter_messages(logs, group, window, ""),
        lambda ms: len(ms) >= len(_LINES), timeout_s=90.0,
        description="FilterLogEvents to see all stored events",
    )
    for key, (pattern, expected) in _PATTERNS.items():
        got = _filter_messages(logs, group, window, pattern)
        assert got == [_LINES[i] for i in expected], (
            f"FilterLogEvents({pattern!r}) returned {got!r}; TestMetricFilter and real AWS match "
            f"exactly {[_LINES[i] for i in expected]!r}"
        )

    # Evaluator 3: the live metric filters, observed as CloudWatch datapoints.
    def _sums():
        end = datetime.now(timezone.utc) + timedelta(minutes=5)
        start = end - timedelta(minutes=20)
        out = {}
        for key in _PATTERNS:
            points = cw.get_metric_statistics(
                Namespace=namespace, MetricName=key, StartTime=start, EndTime=end,
                Period=60, Statistics=["Sum"],
            ).get("Datapoints", [])
            out[key] = sum(p.get("Sum", 0.0) for p in points)
        return out

    sums = _poll_until(
        _sums,
        lambda s: all(s[k] >= len(exp) for k, (_, exp) in _PATTERNS.items()),
        timeout_s=210.0,
        interval_s=10.0,
        description=f"every metric in {namespace} to reach its matched-event count",
    )
    for key, (pattern, expected) in _PATTERNS.items():
        assert sums[key] == float(len(expected)), (
            f"metric filter {pattern!r} published Sum={sums[key]!r}, but FilterLogEvents and "
            f"TestMetricFilter both matched exactly {len(expected)} event(s); all sums: {sums!r}"
        )


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last: {last!r}")


def _filter_messages(logs, group, window, pattern):
    out, token = [], None
    for _ in range(200):
        kwargs = dict(logGroupName=group, **window)
        if pattern:
            kwargs["filterPattern"] = pattern
        if token:
            kwargs["nextToken"] = token
        resp = logs.filter_log_events(**kwargs)
        out.extend(e["message"] for e in resp.get("events", []))
        token = resp.get("nextToken")
        if not token:
            return out
    raise AssertionError("FilterLogEvents pagination did not terminate within 200 pages")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
