"""converse-invocations-reach-cloudwatch-with-the-documented-unit-and-dimension."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "converse-invocations-reach-cloudwatch-with-the-documented-unit-and-dimension"
GROUP = "observability"
SERVICES = ["bedrock-runtime", "cloudwatch"]

# The metric series is shared by every caller of this model, so counts are asserted as floors.
MODEL_ID = "amazon.nova-lite-v1:0"
_NAMESPACE = "AWS/Bedrock"
_DIMENSION = "ModelId"
_PERIOD_S = 60
_INVOCATIONS = 3
_CONVERGE_TIMEOUT_S = 210.0
_LIST_TIMEOUT_S = 120.0
_POLL_S = 2.0
_UNIT_COUNT = "Count"
_UNIT_MS = "Milliseconds"

_PROMPT = "Reply with exactly the single word PONG and nothing else."
_INFERENCE = {"maxTokens": 32, "temperature": 0.0}


def _statistics(cw, metric_name, model_id, start, end):
    """Every datapoint for one metric at one ModelId dimension, Sum and Maximum, with the Unit."""
    return cw.get_metric_statistics(
        Namespace=_NAMESPACE,
        MetricName=metric_name,
        Dimensions=[{"Name": _DIMENSION, "Value": model_id}],
        StartTime=start,
        EndTime=end,
        Period=_PERIOD_S,
        Statistics=["Sum", "Maximum"],
    )["Datapoints"]


def _sum(points) -> float:
    return sum(p["Sum"] for p in points)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# timing:real-time — metric: 59 s https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-runtime-metrics.html
@tags("axis:happy-path", "cap:c3", "concern:metrics", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Converse calls raise the AWS/Bedrock Invocations Sum for their ModelId with Unit Count and
    publish InvocationLatency in Milliseconds, while an invented ModelId has no series.

    Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-runtime-metrics.html
    """
    rt = ctx.client("bedrock-runtime")
    cw = ctx.client("cloudwatch")

    # Unique per run, so nothing can ever have published under this dimension value.
    absent_model = ctx.unique_name("sim2real.no-such-model-")

    window_start = (datetime.datetime.now(datetime.timezone.utc)
                    - datetime.timedelta(seconds=_PERIOD_S))
    baseline_points = _statistics(
        cw, "Invocations", MODEL_ID, window_start,
        datetime.datetime.now(datetime.timezone.utc))
    baseline = _sum(baseline_points)

    latencies_ms = []
    for index in range(_INVOCATIONS):
        resp = rt.converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": _PROMPT}]}],
            inferenceConfig=_INFERENCE,
        )
        assert resp["stopReason"] == "end_turn", (
            f"invocation {index} must succeed for it to be counted as an Invocation at all; got "
            f"stopReason={resp['stopReason']!r}"
        )
        assert resp["usage"]["outputTokens"] > 0, (
            f"invocation {index} billed no output tokens, so it may not be a successful request; "
            f"usage={resp['usage']!r}"
        )
        assert resp["metrics"]["latencyMs"] > 0, (
            f"ConverseResponse.metrics.latencyMs is a required member and must report the "
            f"invocation's own latency; got {resp['metrics']!r}"
        )
        latencies_ms.append(float(resp["metrics"]["latencyMs"]))

    # Bedrock metrics are near-real-time on 1-minute aggregation; the bounded poll waits for them.
    deadline = time.monotonic() + _budget_s(ctx, _CONVERGE_TIMEOUT_S)
    points: list[dict] = []
    delta = 0.0
    while time.monotonic() < deadline:
        points = _statistics(cw, "Invocations", MODEL_ID, window_start,
                             datetime.datetime.now(datetime.timezone.utc))
        delta = _sum(points) - baseline
        if delta >= _INVOCATIONS:
            break
        time.sleep(_POLL_S)
    if not delta >= _INVOCATIONS and _budget_spent(ctx):
        raise TimeoutError(f"the Invocations Sum for {MODEL_ID} rising by {_INVOCATIONS}: "
                           "the run budget ended first; not graded")
    assert delta >= _INVOCATIONS, (
        f"{_INVOCATIONS} successful Converse calls against {MODEL_ID} must raise the AWS/Bedrock "
        f"Invocations Sum for that ModelId by at least {_INVOCATIONS} within "
        f"{_CONVERGE_TIMEOUT_S}s; baseline={baseline} observed delta={delta} "
        f"datapoints={points!r}"
    )

    # The documented Unit, which concurrent traffic cannot affect.
    units = sorted({p["Unit"] for p in points})
    assert units == [_UNIT_COUNT], (
        f"AWS/Bedrock Invocations is documented with Unit {_UNIT_COUNT!r}; the datapoints carried "
        f"{units!r} ({points!r})"
    )
    latency_points = _statistics(cw, "InvocationLatency", MODEL_ID, window_start,
                                 datetime.datetime.now(datetime.timezone.utc))
    assert latency_points, (
        f"InvocationLatency must be published for the same ModelId in the same window as "
        f"Invocations; the Invocations Sum moved by {delta} but InvocationLatency has no datapoint"
    )
    latency_units = sorted({p["Unit"] for p in latency_points})
    assert latency_units == [_UNIT_MS], (
        f"AWS/Bedrock InvocationLatency is documented in milliseconds; the datapoints carried "
        f"{latency_units!r} ({latency_points!r})"
    )
    # Lower bound only: other callers can raise a shared Maximum but never lower it. Latency
    # published in seconds under a Milliseconds unit would be ~1000x too small. The reference is
    # the service's own per-call latencyMs, so client-side load cannot move the floor.
    server_max_ms = max(p["Maximum"] for p in latency_points)
    floor_ms = min(latencies_ms) / 10.0
    assert server_max_ms >= floor_ms, (
        f"the server-reported InvocationLatency maximum is {server_max_ms}ms, below a tenth of "
        f"this run's FASTEST Converse metrics.latencyMs ({min(latencies_ms):.0f}ms). The metric "
        f"cannot be that much smaller than the latency the same service reported per call, so the "
        f"series is publishing the wrong magnitude — seconds under a Milliseconds unit is the "
        f"usual cause. All reported: "
        f"{[round(x) for x in latencies_ms]!r}"
    )
    for point in points:
        assert window_start <= point["Timestamp"], (
            f"a datapoint is stamped before the query window opened, so the series is not being "
            f"binned to real time; window_start={window_start!r} datapoint={point!r}"
        )

    # Terminal read through a different operation; ListMetrics lags GetMetricStatistics.
    list_deadline = time.monotonic() + _budget_s(ctx, _LIST_TIMEOUT_S)
    seen: list[list[dict]] = []
    found = False
    while time.monotonic() < list_deadline:
        seen = []
        paginator = cw.get_paginator("list_metrics")
        for page in paginator.paginate(Namespace=_NAMESPACE, MetricName="Invocations"):
            for metric in page["Metrics"]:
                seen.append(metric["Dimensions"])
        if [{"Name": _DIMENSION, "Value": MODEL_ID}] in seen:
            found = True
            break
        time.sleep(_POLL_S)
    if not found and _budget_spent(ctx):
        raise TimeoutError(f"ListMetrics surfacing {_DIMENSION}={MODEL_ID!r}: "
                           "the run budget ended first; not graded")
    assert found, (
        f"ListMetrics must surface the AWS/Bedrock Invocations series for "
        f"{_DIMENSION}={MODEL_ID!r} within {_LIST_TIMEOUT_S}s of GetMetricStatistics reporting "
        f"{delta} new invocations; the dimension sets it returned were {seen!r}"
    )
    # A target answering from one aggregate series ignores the ModelId dimension.
    assert [{"Name": _DIMENSION, "Value": absent_model}] not in seen, (
        f"ListMetrics returned an AWS/Bedrock Invocations series for {_DIMENSION}="
        f"{absent_model!r}, a model id this run invented and never invoked, so the ModelId "
        f"dimension is not being honoured; dimension sets {seen!r}"
    )
    absent_points = _statistics(cw, "Invocations", absent_model, window_start,
                                datetime.datetime.now(datetime.timezone.utc))
    assert absent_points == [], (
        f"GetMetricStatistics must return no datapoint for {_DIMENSION}={absent_model!r}, which "
        f"names no model and was never invoked; got {absent_points!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
