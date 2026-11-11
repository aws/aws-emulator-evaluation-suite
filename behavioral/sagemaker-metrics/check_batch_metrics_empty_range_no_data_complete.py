"""batch-metrics-empty-range-no-data-complete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-metrics-empty-range-no-data-complete"
GROUP = "state"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query for a metric that exists but whose Start/End window excludes every
    recorded point returns Status=Complete with empty series -- distinct from the
    ValidationError returned for an invalid range."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())

    put_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[{"MetricName": "windowed", "Timestamp": now, "Step": 0, "Value": 7.0}],
    )
    assert not put_resp.get("Errors"), f"BatchPutMetrics reported errors: {put_resp.get('Errors')}"

    in_range_query = {
        "MetricName": "windowed",
        "ResourceArn": tc["arn"],
        "MetricStat": "Last",
        "Period": "IterationNumber",
        "XAxisType": "IterationNumber",
        "Start": 0,
        "End": 5,
    }
    # First confirm the metric really is ingested and queryable (positive control).
    in_range_result = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=[in_range_query])["MetricQueryResults"][0],
        lambda r: r["Status"] == "Complete" and r["MetricValues"],
        timeout_s=90.0,
        interval_s=3.0,
        description="windowed metric to become queryable on the IterationNumber axis",
    )
    assert in_range_result["Status"] == "Complete", (
        f"expected Complete for the in-range positive control, got {in_range_result['Status']!r}: {in_range_result}"
    )
    assert abs(in_range_result["MetricValues"][0] - 7.0) < 1e-6, (
        f"expected the written value 7.0 back from the in-range query, got {in_range_result['MetricValues']!r}"
    )

    # Now query a disjoint step window that excludes the recorded point (Step=0) entirely.
    out_of_range_query = dict(in_range_query, Start=100, End=200)
    out_of_range_result = metrics.batch_get_metrics(MetricQueries=[out_of_range_query])[
        "MetricQueryResults"
    ][0]
    assert out_of_range_result["Status"] == "Complete", (
        f"a query window disjoint from every recorded point should still report Complete "
        f"(not a ValidationError), got {out_of_range_result['Status']!r}: {out_of_range_result}"
    )
    assert out_of_range_result["MetricValues"] == [], (
        f"expected no values for a step window with no recorded point, got {out_of_range_result['MetricValues']!r}"
    )
    assert out_of_range_result["XAxisValues"] == [], (
        f"expected no x-axis values for a step window with no recorded point, got {out_of_range_result['XAxisValues']!r}"
    )


def _create_trial_component(ctx):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-tc-")
    resp = sm.create_trial_component(
        TrialComponentName=name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_trial_component(TrialComponentName=name))
    return {"name": name, "arn": resp["TrialComponentArn"]}


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if predicate(result):
        return result
    raise AssertionError(f"timed out after {timeout_s}s waiting for: {description}; last result: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
