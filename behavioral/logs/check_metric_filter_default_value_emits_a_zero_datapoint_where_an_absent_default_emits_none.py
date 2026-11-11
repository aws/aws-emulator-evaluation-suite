"""metric-filter-default-value-emits-a-zero-datapoint-where-an-absent-default-emits-none."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-filter-default-value-emits-a-zero-datapoint-where-an-absent-default-emits-none"
GROUP = "metric-filters"
SERVICES = ["logs"]

_PATTERN = '"SIM2REALMATCH"'
_WITH_DEFAULT_METRIC = "Sim2RealWithDefault"
_WITHOUT_DEFAULT_METRIC = "Sim2RealWithoutDefault"


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A metric filter with defaultValue=0 publishes a zero datapoint when its pattern does not
    match, while an identical filter with no defaultValue publishes nothing; a matching event
    then yields Sum 1 on both, so "no datapoint" and "a zero datapoint" differ."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    namespace = ctx.unique_name("Sim2RealMFDefault/")
    group = ctx.unique_name("sim2real-behav-logs-mfdefault-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream = ctx.unique_name("sim2real-behav-stream-mfdefault-")
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    # Two filters, identical in every respect except defaultValue, on the SAME log group so
    # they see the SAME events at the SAME instant. That makes the negative leg a twin
    # control group rather than a wait.
    with_default = ctx.unique_name("sim2real-behav-mf-withdefault-")
    without_default = ctx.unique_name("sim2real-behav-mf-nodefault-")
    logs.put_metric_filter(
        logGroupName=group,
        filterName=with_default,
        filterPattern=_PATTERN,
        metricTransformations=[
            {
                "metricName": _WITH_DEFAULT_METRIC,
                "metricNamespace": namespace,
                "metricValue": "1",
                "defaultValue": 0,
            }
        ],
    )
    ctx.on_cleanup(
        lambda: logs.delete_metric_filter(logGroupName=group, filterName=with_default)
    )
    logs.put_metric_filter(
        logGroupName=group,
        filterName=without_default,
        filterPattern=_PATTERN,
        metricTransformations=[
            {
                "metricName": _WITHOUT_DEFAULT_METRIC,
                "metricNamespace": namespace,
                "metricValue": "1",
            }
        ],
    )
    ctx.on_cleanup(
        lambda: logs.delete_metric_filter(logGroupName=group, filterName=without_default)
    )

    described = logs.describe_metric_filters(logGroupName=group, filterNamePrefix=with_default)
    tx = described["metricFilters"][0]["metricTransformations"][0]
    assert tx["defaultValue"] == 0.0, (
        f"expected DescribeMetricFilters to echo defaultValue 0 for {with_default}, got "
        f"{tx.get('defaultValue')!r}"
    )

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)

    # --- Phase 1: an event that the pattern does NOT match.
    _write(logs, group, stream, "a quiet line the pattern does not match")

    with_dps = _poll_until(
        lambda: _stats(cw, namespace, _WITH_DEFAULT_METRIC, window_start),
        lambda dps: bool(dps),
        timeout_s=300.0,
        interval_s=15.0,
        description=(
            f"the defaultValue filter {with_default} publishes a datapoint for a period in "
            f"which its pattern matched nothing"
        ),
    )
    with_sum = sum(dp["Sum"] for dp in with_dps)
    with_samples = sum(dp["SampleCount"] for dp in with_dps)
    assert with_samples >= 1.0 and with_sum == 0.0, (
        f"expected a real ZERO datapoint from the defaultValue filter: SampleCount >= 1 with "
        f"Sum == 0, got SampleCount {with_samples} and Sum {with_sum}; Sum 1 would mean the "
        f"non-matching event was counted as a match"
    )

    # --- Phase 1 twin control, in the same instant, against a filter now proven live on the
    # same log group and the same pattern: no default, so no datapoint.
    without_dps = _stats(cw, namespace, _WITHOUT_DEFAULT_METRIC, window_start)
    assert not without_dps, (
        f"expected ZERO datapoints for {_WITHOUT_DEFAULT_METRIC}: it declares no "
        f"defaultValue, and its twin on the same log group with the same pattern just "
        f"published a zero datapoint, so the wiring demonstrably works; got {without_dps!r}"
    )

    # --- Phase 2: the mandatory positive control for the no-default filter. Without this
    # leg, phase 1 cannot tell "no defaultValue means no datapoint" from "this filter never
    # emits anything".
    _write(logs, group, stream, "SIM2REALMATCH the pattern does match this one")

    without_after = _poll_until(
        lambda: _stats(cw, namespace, _WITHOUT_DEFAULT_METRIC, window_start),
        lambda dps: bool(dps),
        timeout_s=300.0,
        interval_s=15.0,
        description=(
            f"positive control: {without_default} publishes a datapoint once its pattern "
            f"actually matches"
        ),
    )
    without_sum = sum(dp["Sum"] for dp in without_after)
    assert without_sum == 1.0, (
        f"expected Sum == 1 for the no-default filter after exactly one matching event, got "
        f"{without_sum}"
    )

    with_after = _poll_until(
        lambda: _stats(cw, namespace, _WITH_DEFAULT_METRIC, window_start),
        lambda dps: sum(d["Sum"] for d in dps) == 1.0,
        timeout_s=300.0,
        interval_s=15.0,
        description=(
            "the defaultValue filter's window Sum reaches exactly 1 (its zero periods "
            "contribute nothing, the one match contributes 1)"
        ),
    )
    with_after_sum = sum(dp["Sum"] for dp in with_after)
    with_after_samples = sum(dp["SampleCount"] for dp in with_after)
    assert with_after_sum == 1.0 and with_after_samples > with_samples, (
        f"expected the defaultValue filter to end at Sum == 1 with strictly more samples "
        f"than the {with_samples} it had before the match (the zero periods are still "
        f"counted), got Sum {with_after_sum} with SampleCount {with_after_samples}"
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


def _write(logs, group: str, stream: str, message: str) -> None:
    resp = logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": _now_ms(), "message": message}],
    )
    rejected = resp.get("rejectedLogEventsInfo")
    assert not rejected, (
        f"expected the in-window event accepted for {group}, got rejectedLogEventsInfo "
        f"{rejected!r}"
    )


def _stats(cw, namespace, metric_name, start):
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
        Period=60,
        Statistics=["Sum", "SampleCount"],
    )
    return resp["Datapoints"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
