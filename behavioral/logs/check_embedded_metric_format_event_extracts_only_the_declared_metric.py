"""embedded-metric-format-event-extracts-only-the-declared-metric."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "embedded-metric-format-event-extracts-only-the-declared-metric"
GROUP = "telemetry"
SERVICES = ["logs"]

_DIM_NAME = "Sim2RealOp"
_DIM_VALUE = "Store"
_DECLARED_METRIC = "Sim2RealDeclaredLatency"
_UNDECLARED_METRIC = "Sim2RealUndeclaredLatency"
_DECLARED_VALUE = 137.5
_UNDECLARED_VALUE = 987.0
_NON_EMF_VALUE = 555.0
_DECLARED_UNIT = "Milliseconds"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """An embedded-metric-format event publishes only the metric declared in _aws.CloudWatchMetrics, with the
    declared value and unit; its undeclared numeric field and a non-EMF twin event publish nothing, and both
    events are stored unchanged.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    namespace = ctx.unique_name("Sim2RealEMF/")
    group = ctx.unique_name("sim2real-behav-logs-emf-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream = ctx.unique_name("sim2real-behav-stream-emf-")
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    ts = _now_ms()
    marker = ctx.unique_name("emf-marker-")

    # Both events carry the same field names; only the _aws block differs, so the negative
    # legs are twin controls written in the same batch as the positive.
    emf_event = {
        "_aws": {
            "Timestamp": ts,
            "CloudWatchMetrics": [
                {
                    "Namespace": namespace,
                    "Dimensions": [[_DIM_NAME]],
                    "Metrics": [{"Name": _DECLARED_METRIC, "Unit": _DECLARED_UNIT}],
                }
            ],
        },
        _DIM_NAME: _DIM_VALUE,
        _DECLARED_METRIC: _DECLARED_VALUE,
        _UNDECLARED_METRIC: _UNDECLARED_VALUE,
        "Marker": marker,
    }
    non_emf_event = {
        _DIM_NAME: _DIM_VALUE,
        _DECLARED_METRIC: _NON_EMF_VALUE,
        _UNDECLARED_METRIC: _UNDECLARED_VALUE,
        "Marker": marker,
    }
    emf_body = json.dumps(emf_event, sort_keys=True)
    non_emf_body = json.dumps(non_emf_event, sort_keys=True)

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    resp = logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": ts, "message": emf_body},
            {"timestamp": ts + 1, "message": non_emf_body},
        ],
    )
    rejected = resp.get("rejectedLogEventsInfo")
    assert not rejected, (
        f"expected both in-window events accepted, got rejectedLogEventsInfo {rejected!r}"
    )

    dims = [{"Name": _DIM_NAME, "Value": _DIM_VALUE}]

    # EMF needs no metric filter or PutMetricData permission; extraction is asynchronous.
    declared = _poll_until(
        lambda: _stats(cw, namespace, _DECLARED_METRIC, dims, window_start),
        lambda dps: bool(dps),
        timeout_s=_capped(ctx, 420.0),
        interval_s=2.0,
        description=(
            f"the EMF-declared metric {namespace}/{_DECLARED_METRIC} becomes readable "
            f"after PutLogEvents of an EMF event (no metric filter configured)"
        ),
    )

    minima = {dp["Minimum"] for dp in declared}
    maxima = {dp["Maximum"] for dp in declared}
    assert minima == {_DECLARED_VALUE} and maxima == {_DECLARED_VALUE}, (
        f"expected every extracted sample of {_DECLARED_METRIC} to carry exactly the "
        f"declared value {_DECLARED_VALUE}, got minima {sorted(minima)} and maxima "
        f"{sorted(maxima)}; a maximum of {_NON_EMF_VALUE} means the non-EMF event was "
        f"also turned into a metric"
    )
    sample_count = sum(dp["SampleCount"] for dp in declared)
    total = sum(dp["Sum"] for dp in declared)
    assert sample_count >= 1.0 and total == sample_count * _DECLARED_VALUE, (
        f"expected Sum == SampleCount * {_DECLARED_VALUE} (EMF guarantees at-least-once "
        f"delivery, so duplicates are permitted but every sample must be the declared "
        f"value), got Sum {total} with SampleCount {sample_count}"
    )
    units = {dp["Unit"] for dp in declared}
    assert units == {_DECLARED_UNIT}, (
        f"expected the extracted datapoints to carry the unit declared inside "
        f"_aws.CloudWatchMetrics ({_DECLARED_UNIT!r}), got {sorted(units)}"
    )

    # Absence by contrast: the declared metric from the SAME event has landed, so one extraction
    # of that event is done; the undeclared field is read once through two CloudWatch operations.
    undeclared = _stats(cw, namespace, _UNDECLARED_METRIC, dims, window_start)
    assert not undeclared, (
        f"expected NO datapoints for {_UNDECLARED_METRIC}: it is a numeric top-level "
        f"field of the same EMF event but is not named in "
        f"_aws.CloudWatchMetrics[].Metrics, so it must not become a metric; got "
        f"{undeclared!r}"
    )
    values = _metric_data_values(cw, namespace, _UNDECLARED_METRIC, dims, window_start)
    assert not values, (
        f"expected GetMetricData to return no values for the undeclared field "
        f"{_UNDECLARED_METRIC} (second, independent observable of absence), got {values!r}"
    )

    # Extraction does not consume the events. GetLogEvents, not FilterLogEvents: filter-pattern
    # search can lag stream reads by minutes for freshly written events.
    stored = _poll_until(
        lambda: _stored_messages(logs, group, stream),
        lambda msgs: len(msgs) == 2,
        timeout_s=_capped(ctx, 120.0),
        interval_s=2.0,
        description="both written events readable back through GetLogEvents",
    )
    assert stored == sorted([emf_body, non_emf_body]), (
        "expected both events stored byte-identically -- metric extraction must not "
        f"rewrite or strip the _aws block; got {len(stored)} messages that differ from "
        f"the two written bodies (first divergence: {_first_divergence(stored, sorted([emf_body, non_emf_body]))})"
    )


def _now_ms() -> int:
    return int(time.time() * 1000)


def _capped(ctx, own_s: float) -> float:
    """``own_s`` capped by the time the run has left, so a slow target fails with its own message."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - 10.0))


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; raise on the deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _stats(cw, namespace, metric_name, dimensions, start):
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
        Period=60,
        Statistics=["Sum", "SampleCount", "Minimum", "Maximum"],
    )
    return resp["Datapoints"]


def _metric_data_values(cw, namespace, metric_name, dimensions, start):
    resp = cw.get_metric_data(
        MetricDataQueries=[
            {
                "Id": "probe",
                "MetricStat": {
                    "Metric": {
                        "Namespace": namespace,
                        "MetricName": metric_name,
                        "Dimensions": dimensions,
                    },
                    "Period": 60,
                    "Stat": "Sum",
                },
                "ReturnData": True,
            }
        ],
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
    )
    return resp["MetricDataResults"][0]["Values"]


def _stored_messages(logs, group: str, stream: str) -> list[str]:
    resp = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True)
    return sorted(e["message"] for e in resp["events"])


def _first_divergence(got: list[str], want: list[str]) -> str:
    for g, w in zip(got, want):
        if g != w:
            return f"{g[:80]!r} != {w[:80]!r}"
    return f"length {len(got)} != {len(want)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
