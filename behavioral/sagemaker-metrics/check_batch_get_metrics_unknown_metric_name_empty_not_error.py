"""batch-get-metrics-unknown-metric-name-empty-not-error."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-get-metrics-unknown-metric-name-empty-not-error"
GROUP = "state"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """In one BatchGetMetrics request, a query for a metric never written resolves to Complete with
    empty MetricValues and XAxisValues, while a query for a written metric returns its value 1.0."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())

    put_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[{"MetricName": "known", "Timestamp": now, "Step": 0, "Value": 1.0}],
    )
    assert not put_resp.get("Errors"), f"expected no errors putting known metric, got {put_resp.get('Errors')}"

    known_query = {
        "MetricName": "known",
        "ResourceArn": tc["arn"],
        "MetricStat": "Last",
        "Period": "IterationNumber",
        "XAxisType": "IterationNumber",
    }
    unknown_query = dict(known_query, MetricName="never-written-metric-name")

    results = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=[known_query, unknown_query])[
            "MetricQueryResults"
        ],
        lambda rs: rs[0]["Status"] == "Complete" and rs[0]["MetricValues"],
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert results[0]["Status"] == "Complete", f"expected Complete for known metric, got {results[0]}"
    assert abs(results[0]["MetricValues"][0] - 1.0) < 1e-6, (
        f"expected known metric value 1.0, got {results[0]['MetricValues']}"
    )
    assert results[1]["Status"] == "Complete", f"unexpected status for unknown metric name: {results[1]}"
    assert results[1]["MetricValues"] == [], f"expected empty MetricValues for unknown metric name, got {results[1]['MetricValues']}"
    assert results[1]["XAxisValues"] == [], f"expected empty XAxisValues for unknown metric name, got {results[1]['XAxisValues']}"


def _create_trial_component(ctx):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-tc-")
    resp = sm.create_trial_component(TrialComponentName=name)
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
    raise TimeoutError(f"condition not met within {timeout_s}s; last result: {result}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
