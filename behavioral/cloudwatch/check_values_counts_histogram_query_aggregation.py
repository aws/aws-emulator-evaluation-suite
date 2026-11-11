"""values-counts-histogram-query-aggregation."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "values-counts-histogram-query-aggregation"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']


# ===== helpers =====
def _poll_until(ctx, probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of its refusal, raising if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal but the call succeeded: {result!r}")
# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutMetricData Values/Counts histogram aggregates as a WEIGHTED multiset (SampleCount
    is sum(Counts), Sum is sum(v*c), Average derives from those), and a batch rejected for a
    malformed member is rejected atomically: its valid sibling datum is never ingested."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-behav-cwprobe-ns-histogram-")
    metric = "RequestDuration"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(minutes=10)
    end = now + timedelta(minutes=5)

    values = [10.0, 20.0, 30.0]
    counts = [1.0, 2.0, 3.0]
    exp_samples = sum(counts)                                    # 6
    exp_sum = sum(v * c for v, c in zip(values, counts))          # 140
    exp_avg = exp_sum / exp_samples                              # 23.333...

    cw.put_metric_data(
        Namespace=ns,
        MetricData=[
            {
                "MetricName": metric,
                "Timestamp": now,
                "Values": values,
                "Counts": counts,
                "Unit": "Milliseconds",
            }
        ],
    )

    def stats(name):
        return cw.get_metric_statistics(
            Namespace=ns,
            MetricName=name,
            StartTime=start,
            EndTime=end,
            Period=3600,
            Statistics=["Sum", "SampleCount", "Minimum", "Maximum", "Average"],
        ).get("Datapoints", [])

    dps = _poll_until(
        ctx,
        lambda: stats(metric),
        lambda d: len(d) > 0,
        timeout_s=120,
        interval_s=2,
        description="the Values/Counts histogram datum to become queryable",
    )
    dp = dps[0]
    assert dp["SampleCount"] == exp_samples, (
        f"SampleCount must be sum(Counts)={exp_samples} (each Values[i] weighted by Counts[i]), "
        f"not len(Values)={len(values)}; got {dp['SampleCount']}"
    )
    assert dp["Sum"] == exp_sum, (
        f"Sum must be sum(Values[i]*Counts[i])={exp_sum}, not sum(Values)={sum(values)}; got {dp['Sum']}"
    )
    assert dp["Minimum"] == min(values), f"expected Minimum={min(values)}, got {dp['Minimum']}"
    assert dp["Maximum"] == max(values), f"expected Maximum={max(values)}, got {dp['Maximum']}"
    assert abs(dp["Average"] - exp_avg) < 1e-6, (
        f"Average must be the weighted mean {exp_avg} (=Sum/SampleCount), not the unweighted "
        f"mean {sum(values) / len(values)}; got {dp['Average']}"
    )

    # --- Deep negative: Counts shorter than Values, batched with a valid sibling ---
    sibling = "SiblingShouldNotBeIngested"
    code, message = _err(lambda: cw.put_metric_data(
        Namespace=ns,
        MetricData=[
            {"MetricName": sibling, "Timestamp": now, "Value": 999.0, "Unit": "Milliseconds"},
            {
                "MetricName": "MismatchedHistogram",
                "Timestamp": now,
                "Values": [1.0, 2.0, 3.0],
                "Counts": [1.0, 2.0],  # one short -- must be rejected
                "Unit": "Milliseconds",
            },
        ],
    ))
    # Real AWS refuses the length mismatch as InvalidParameterValue.
    assert code == "InvalidParameterValue", (
        f"a Counts array shorter than Values must be rejected with InvalidParameterValue, "
        f"got {code!r}: {message!r}"
    )
    assert message == (
        "The parameters MetricData.member.2.Values and MetricData.member.2.Counts must be of the same size."
    ), message
    # Effect absent, by contrast: a valid datum published AFTER the rejected batch becomes
    # queryable first, so a sibling ingested from that batch would be visible by then too.
    contrast = "ContrastAfterRejection"
    cw.put_metric_data(
        Namespace=ns,
        MetricData=[{"MetricName": contrast, "Timestamp": now, "Value": 1.0, "Unit": "Milliseconds"}],
    )
    _poll_until(
        ctx,
        lambda: stats(contrast),
        lambda d: len(d) > 0,
        timeout_s=120,
        interval_s=2,
        description="the contrast datum published after the rejected batch to become queryable",
    )
    # The sibling stays absent for a further 20s, so a late ingestion is caught too.
    hold_end = time.monotonic() + 20.0
    while True:
        leaked = stats(sibling)
        assert leaked == [], (
            "a PutMetricData batch rejected for a malformed member must be rejected "
            f"atomically -- the valid sibling datum must not be ingested -- observed {leaked!r}"
        )
        if time.monotonic() >= hold_end:
            break
        time.sleep(2)

    # --- Deep negative: Value and Values are mutually exclusive input modes ---
    code, message = _err(lambda: cw.put_metric_data(
        Namespace=ns,
        MetricData=[{
            "MetricName": "BothValueAndValues",
            "Timestamp": now,
            "Value": 5.0,
            "Values": [5.0],
            "Counts": [1.0],
        }],
    ))
    assert code == "InvalidParameterCombination", (
        f"Value and Values are mutually exclusive input modes; expected "
        f"InvalidParameterCombination, got {code!r}: {message!r}"
    )
    assert message == (
        "The parameters MetricData.member.1.Value and MetricData.member.1.Values are mutually "
        "exclusive and you have specified both."
    ), message

    # --- Control: the valid histogram datum is unchanged and still queryable ---
    control = stats(metric)
    assert control and control[0]["SampleCount"] == exp_samples and control[0]["Sum"] == exp_sum, (
        f"the accepted histogram datum must be unaffected by the rejected calls, got {control}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
