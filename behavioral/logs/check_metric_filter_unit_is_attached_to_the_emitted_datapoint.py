"""metric-filter-unit-is-attached-to-the-emitted-datapoint."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-filter-unit-is-attached-to-the-emitted-datapoint"
GROUP = "metric-filters"
SERVICES = ["logs"]

_DECLARED_UNIT = "Milliseconds"
_WRONG_UNIT = "Bytes"
_UNITED_METRIC = "Sim2RealElapsedWithUnit"
_UNITLESS_METRIC = "Sim2RealElapsedNoUnit"
_VALUE = 250.0


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:metrics",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A metric filter's declared unit is attached to the CloudWatch datapoint it emits:
    the datapoint is served under that unit and not under another, while a sibling filter
    that declares no unit emits an unqualified datapoint."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    namespace = ctx.unique_name("Sim2RealMFUnit/")
    group = ctx.unique_name("sim2real-behav-logs-mfunit-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream = ctx.unique_name("sim2real-behav-stream-mfunit-")
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    united_filter = ctx.unique_name("sim2real-behav-mf-united-")
    unitless_filter = ctx.unique_name("sim2real-behav-mf-unitless-")

    logs.put_metric_filter(
        logGroupName=group,
        filterName=united_filter,
        filterPattern="[level, dur]",
        metricTransformations=[
            {
                "metricName": _UNITED_METRIC,
                "metricNamespace": namespace,
                "metricValue": "$dur",
                "unit": _DECLARED_UNIT,
            }
        ],
    )
    ctx.on_cleanup(
        lambda: logs.delete_metric_filter(logGroupName=group, filterName=united_filter)
    )
    logs.put_metric_filter(
        logGroupName=group,
        filterName=unitless_filter,
        filterPattern="[level, dur]",
        metricTransformations=[
            {
                "metricName": _UNITLESS_METRIC,
                "metricNamespace": namespace,
                "metricValue": "$dur",
            }
        ],
    )
    ctx.on_cleanup(
        lambda: logs.delete_metric_filter(logGroupName=group, filterName=unitless_filter)
    )

    # --- 1. The declaration round-trips, and its absence round-trips too.
    united_tx = _transformation(logs, group, united_filter)
    assert united_tx["unit"] == _DECLARED_UNIT, (
        f"expected DescribeMetricFilters to echo unit {_DECLARED_UNIT!r} for "
        f"{united_filter}, got {united_tx.get('unit')!r}"
    )
    unitless_tx = _transformation(logs, group, unitless_filter)
    assert "unit" not in unitless_tx, (
        f"expected NO unit key for a transformation that declared none, got "
        f"{unitless_tx.get('unit')!r} in {unitless_tx!r}"
    )

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    resp = logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": _now_ms(), "message": f"OK {int(_VALUE)}"}],
    )
    rejected = resp.get("rejectedLogEventsInfo")
    assert not rejected, f"expected the event accepted, got rejectedLogEventsInfo {rejected!r}"

    # --- 2. Positive control on BOTH filters: each emits its datapoint with the value the
    # pattern extracted. Without this, the two absence legs below could pass against a
    # target that emits nothing at all.
    united = _poll_until(
        lambda: _stats(cw, namespace, _UNITED_METRIC, window_start, unit=_DECLARED_UNIT),
        lambda dps: bool(dps),
        timeout_s=300.0,
        interval_s=15.0,
        description=(
            f"{namespace}/{_UNITED_METRIC} becomes readable under Unit={_DECLARED_UNIT}"
        ),
    )
    united_sum = sum(dp["Sum"] for dp in united)
    assert united_sum == _VALUE, (
        f"expected Sum == {_VALUE} (metricValue '$dur' extracted from 'OK {int(_VALUE)}'), "
        f"got {united_sum}"
    )
    united_units = {dp["Unit"] for dp in united}
    assert united_units == {_DECLARED_UNIT}, (
        f"expected the emitted datapoints to carry the declared unit {_DECLARED_UNIT!r}, got "
        f"{sorted(united_units)}"
    )

    unitless = _poll_until(
        lambda: _stats(cw, namespace, _UNITLESS_METRIC, window_start),
        lambda dps: bool(dps),
        timeout_s=300.0,
        interval_s=15.0,
        description=f"{namespace}/{_UNITLESS_METRIC} becomes readable with no unit filter",
    )
    unitless_sum = sum(dp["Sum"] for dp in unitless)
    assert unitless_sum == _VALUE, (
        f"expected the unitless filter to extract the same value {_VALUE}, got {unitless_sum}"
    )
    unitless_units = {dp["Unit"] for dp in unitless}
    assert unitless_units == {"None"}, (
        f"expected a transformation with no declared unit to emit datapoints with Unit "
        f"'None', got {sorted(unitless_units)}"
    )

    # --- 3. Twin controls in the SAME instant, against datapoints already proven present:
    # the unit is part of the datapoint's identity, so the wrong unit matches nothing.
    wrong_unit = _stats(cw, namespace, _UNITED_METRIC, window_start, unit=_WRONG_UNIT)
    assert not wrong_unit, (
        f"expected ZERO datapoints for {_UNITED_METRIC} under Unit={_WRONG_UNIT!r} -- the "
        f"same query under Unit={_DECLARED_UNIT!r} just returned Sum {united_sum}, so a "
        f"non-empty answer here means the declared unit was dropped and every unit matches; "
        f"got {wrong_unit!r}"
    )
    unitless_as_ms = _stats(cw, namespace, _UNITLESS_METRIC, window_start, unit=_DECLARED_UNIT)
    assert not unitless_as_ms, (
        f"expected ZERO datapoints for {_UNITLESS_METRIC} under Unit={_DECLARED_UNIT!r} -- it "
        f"declared no unit, so the unit cannot be a per-namespace constant; got "
        f"{unitless_as_ms!r}"
    )


def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; RAISE on the deadline (never return last)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _transformation(logs, group: str, filter_name: str) -> dict:
    described = logs.describe_metric_filters(logGroupName=group, filterNamePrefix=filter_name)
    filters = described["metricFilters"]
    assert len(filters) == 1, (
        f"expected exactly 1 metric filter named {filter_name!r} on {group}, got "
        f"{[f['filterName'] for f in filters]}"
    )
    transformations = filters[0]["metricTransformations"]
    assert len(transformations) == 1, (
        f"expected exactly 1 metricTransformation on {filter_name!r}, got {transformations!r}"
    )
    return transformations[0]


def _stats(cw, namespace, metric_name, start, unit=None):
    kwargs = {
        "Namespace": namespace,
        "MetricName": metric_name,
        "StartTime": start,
        "EndTime": datetime.now(timezone.utc) + timedelta(minutes=1),
        "Period": 60,
        "Statistics": ["Sum", "SampleCount"],
    }
    if unit is not None:
        kwargs["Unit"] = unit
    return cw.get_metric_statistics(**kwargs)["Datapoints"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
