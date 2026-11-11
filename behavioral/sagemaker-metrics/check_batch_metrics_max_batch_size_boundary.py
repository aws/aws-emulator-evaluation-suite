"""batch-metrics-max-batch-size-boundary."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-metrics-max-batch-size-boundary"
GROUP = "state"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BatchPutMetrics call with exactly the maximum of 10 RawMetricData items
    ingests all 10 -- none are silently dropped."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())
    n = 10

    put_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[
            {"MetricName": f"m{i}", "Timestamp": now, "Step": 0, "Value": float(i)}
            for i in range(n)
        ],
    )
    errors = put_resp.get("Errors")
    assert not errors, f"expected no Errors for a 10-item (max) BatchPutMetrics call, got {errors!r}"

    def make_query(i):
        return {
            "MetricName": f"m{i}",
            "ResourceArn": tc["arn"],
            "MetricStat": "Last",
            "Period": "IterationNumber",
            "XAxisType": "IterationNumber",
        }

    queries = [make_query(i) for i in range(n)]
    results = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=queries)["MetricQueryResults"],
        lambda rs: all(r["Status"] == "Complete" and r["MetricValues"] for r in rs),
        timeout_s=90.0,
        interval_s=3.0,
        reason="all 10 BatchGetMetrics query results reaching Complete with values",
    )
    assert len(results) == n, f"expected {n} MetricQueryResults, got {len(results)}"
    for i, r in enumerate(results):
        assert r["Status"] == "Complete", f"query {i} (m{i}): expected Status Complete, got {r['Status']!r}"
        got = r["MetricValues"][0]
        assert abs(got - float(i)) < 1e-6, f"query {i} (m{i}): expected value {float(i)}, got {got}"


def _create_trial_component(ctx):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-tc-")
    resp = sm.create_trial_component(
        TrialComponentName=name,
        Tags=[{"Key": "sim2real", "Value": "batch-metrics-max-batch-size-boundary"}],
    )
    ctx.on_cleanup(lambda: sm.delete_trial_component(TrialComponentName=name))
    return {"name": name, "arn": resp["TrialComponentArn"]}


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, reason="condition"):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    if predicate(result):
        return result
    raise TimeoutError(f"timed out after {timeout_s}s waiting for: {reason}; last result: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
