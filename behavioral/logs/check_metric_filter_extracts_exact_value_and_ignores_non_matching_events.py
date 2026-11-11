"""metric-filter-extracts-exact-value-and-ignores-non-matching-events."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-filter-extracts-exact-value-and-ignores-non-matching-events"
GROUP = 'metric-filters'
SERVICES = ['logs']

_LATENCIES = [10, 20, 70]
_EXPECTED_SUM = float(sum(_LATENCIES))
_EXPECTED_MAX = float(max(_LATENCIES))
_EXPECTED_SAMPLES = float(len(_LATENCIES))
_DIMENSION = {"Name": "Service", "Value": "checkout"}


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
    """A metric filter whose metricValue is extracted from a JSON field publishes EXACTLY that value
    (Sum, Maximum, SampleCount) under EXACTLY the declared dimension set, and a non-matching event
    publishes nothing; the dimensioned/undimensioned query pair proves the dimension set.
    """
    svc = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    group = ctx.unique_name("sim2real-behav-lg-mfexact-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    namespace = ctx.unique_name("sim2real-behav-mfexact-ns-")
    metric_name = "ExtractedLatency"
    filter_name = ctx.unique_name("sim2real-behav-mfexact-")

    svc.put_metric_filter(
        logGroupName=group,
        filterName=filter_name,
        filterPattern="{$.latency > 0}",
        metricTransformations=[
            {
                "metricName": metric_name,
                "metricNamespace": namespace,
                "metricValue": "$.latency",
                "dimensions": {_DIMENSION["Name"]: "$.service"},
                # defaultValue is deliberately ABSENT: with it set, a non-matching
                # event publishes the default and the SampleCount assertion below
                # could no longer distinguish "ignored the pattern" from "matched".
            }
        ],
    )
    ctx.on_cleanup(
        lambda _g=group, _f=filter_name: svc.delete_metric_filter(
            logGroupName=_g, filterName=_f
        )
    )

    matching = [
        json.dumps({"service": _DIMENSION["Value"], "latency": v, "marker": f"sim2real-lat-{v}"})
        for v in _LATENCIES
    ]
    non_matching = json.dumps(
        {"service": _DIMENSION["Value"], "marker": "sim2real-no-latency-field"}
    )

    base = _now_ms() - 4000
    resp = svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base + i * 100, "message": msg}
            for i, msg in enumerate(matching + [non_matching])
        ],
    )
    assert "rejectedLogEventsInfo" not in resp, (
        f"the fixture batch was partially rejected, so the metric assertions below would be over "
        f"fewer than {len(_LATENCIES)!r} matching events: {resp!r}"
    )

    def _stats(dimensions):
        """CloudWatch metric data is 1-minute resolution, so the window is wide and
        Period is 60; the datum may land in any minute inside it."""
        end = datetime.now(timezone.utc) + timedelta(minutes=5)
        start = end - timedelta(minutes=20)
        points = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=["Sum", "SampleCount", "Maximum"],
        ).get("Datapoints", [])
        return {
            "points": points,
            "sum": sum(p.get("Sum", 0.0) for p in points),
            "samples": sum(p.get("SampleCount", 0.0) for p in points),
            "max": max((p.get("Maximum", 0.0) for p in points), default=0.0),
        }

    # Metric publication is asynchronous. The observable condition is SampleCount
    # reaching the number of MATCHING events -- not elapsed time, and not the metric
    # appearing in a catalogue.
    dimensioned = _poll_until(
        lambda: _stats([_DIMENSION]),
        lambda s: s["samples"] >= _EXPECTED_SAMPLES,
        timeout_s=210,
        interval_s=10.0,
        description=(
            f"CloudWatch reports SampleCount {_EXPECTED_SAMPLES!r} for {namespace}/{metric_name} "
            f"under {_DIMENSION!r}"
        ),
    )

    assert dimensioned["samples"] == _EXPECTED_SAMPLES, (
        f"metric SampleCount is {dimensioned['samples']!r}; {len(_LATENCIES)!r} matching events "
        "were written and the 1 non-matching event must not have incremented it (datapoints: "
        f"{dimensioned['points']!r})"
    )
    assert dimensioned["sum"] == _EXPECTED_SUM, (
        f"metric Sum is {dimensioned['sum']!r}, expected exactly {_EXPECTED_SUM!r} from the "
        f"extracted latency values {_LATENCIES!r} -- a filter that published the event COUNT "
        f"instead of the extracted value would report {_EXPECTED_SAMPLES!r}"
    )
    assert dimensioned["max"] == _EXPECTED_MAX, (
        f"metric Maximum is {dimensioned['max']!r}, expected {_EXPECTED_MAX!r} -- this fails if "
        "the filter published a constant instead of the per-event extracted value"
    )

    # The dimension set is part of the metric's identity: a datum published under
    # Service=checkout must NOT be retrievable dimensionless, which is what proves
    # the declared dimension was actually attached rather than dropped.
    bare = _stats([])
    assert bare["points"] == [], (
        "the metric filter declared dimensions "
        f"{[_DIMENSION]!r}, so the datum must not be retrievable with no dimensions; "
        f"GetMetricStatistics returned {bare['points']!r} -- an emulator that ignores the "
        "declared dimensions publishes a bare metric and is caught here"
    )

    # The non-matching event published nothing, but it must still be STORED: a metric
    # filter is an observer, not a gate on ingestion.
    stored: list[str] = []
    token = None
    while True:
        kwargs = {"logGroupName": group}
        if token is not None:
            kwargs["nextToken"] = token
        page = svc.filter_log_events(**kwargs)
        stored.extend(e["message"] for e in page.get("events", []))
        token = page.get("nextToken")
        if not token:
            break
    assert non_matching in stored, (
        "sanity: the non-matching event must still be STORED even though it published no metric; "
        f"FilterLogEvents returned {stored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
