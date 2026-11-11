"""batch-metrics-trial-component-isolation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-metrics-trial-component-isolation"
GROUP = "state"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two trial components that record a metric with the same name and step keep
    independent values -- a query against one never returns the other's data."""
    tc1 = _create_trial_component(ctx)
    tc2 = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())

    put1 = metrics.batch_put_metrics(
        TrialComponentName=tc1["name"],
        MetricData=[{"MetricName": "shared", "Timestamp": now, "Step": 0, "Value": 100.0}],
    )
    put2 = metrics.batch_put_metrics(
        TrialComponentName=tc2["name"],
        MetricData=[{"MetricName": "shared", "Timestamp": now, "Step": 0, "Value": 200.0}],
    )
    assert not put1.get("Errors"), f"BatchPutMetrics on tc1 reported errors: {put1.get('Errors')}"
    assert not put2.get("Errors"), f"BatchPutMetrics on tc2 reported errors: {put2.get('Errors')}"

    def make_query(arn):
        return {
            "MetricName": "shared",
            "ResourceArn": arn,
            "MetricStat": "Last",
            "Period": "IterationNumber",
            "XAxisType": "IterationNumber",
        }

    queries = [make_query(tc1["arn"]), make_query(tc2["arn"])]
    results = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=queries)["MetricQueryResults"],
        lambda rs: all(r["Status"] == "Complete" and r["MetricValues"] for r in rs),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert abs(results[0]["MetricValues"][0] - 100.0) < 1e-6, (
        f"tc1 query should read back its own value 100.0, got {results[0]['MetricValues'][0]}"
    )
    assert abs(results[1]["MetricValues"][0] - 200.0) < 1e-6, (
        f"tc2 query should read back its own value 200.0, not tc1's 100.0 -- got {results[1]['MetricValues'][0]}"
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


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if predicate(result):
        return result
    raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
