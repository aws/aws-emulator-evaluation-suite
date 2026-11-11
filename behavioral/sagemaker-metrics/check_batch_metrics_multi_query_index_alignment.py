"""batch-metrics-multi-query-index-alignment."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-metrics-multi-query-index-alignment"
GROUP = "state"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetMetrics returns MetricQueryResults in the same order as the submitted
    MetricQueries, even when that order does not match insertion/alphabetical order."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())

    put_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[
            {"MetricName": "m1", "Timestamp": now, "Step": 0, "Value": 1.0},
            {"MetricName": "m2", "Timestamp": now, "Step": 0, "Value": 2.0},
        ],
    )
    assert not put_resp.get("Errors"), f"expected no BatchPutMetrics errors, got {put_resp.get('Errors')}"

    def make_query(name):
        return {
            "MetricName": name,
            "ResourceArn": tc["arn"],
            "MetricStat": "Last",
            "Period": "IterationNumber",
            "XAxisType": "IterationNumber",
        }

    # Deliberately request m2 before m1 -- reversed from insertion order.
    queries = [make_query("m2"), make_query("m1")]
    results = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=queries)["MetricQueryResults"],
        lambda rs: all(r["Status"] == "Complete" and r["MetricValues"] for r in rs),
        timeout_s=90.0,
        interval_s=3.0,
        reason="BatchGetMetrics results for m2,m1 to reach Status=Complete with values",
    )
    assert len(results) == 2, f"expected 2 MetricQueryResults (one per query), got {len(results)}"
    assert results[0]["Status"] == "Complete" and abs(results[0]["MetricValues"][0] - 2.0) < 1e-6, (
        f"expected result[0] (query for m2) to be Complete with value 2.0, got {results[0]}"
    )
    assert results[1]["Status"] == "Complete" and abs(results[1]["MetricValues"][0] - 1.0) < 1e-6, (
        f"expected result[1] (query for m1) to be Complete with value 1.0, got {results[1]}"
    )


def _create_trial_component(ctx):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-tc-")
    resp = sm.create_trial_component(
        TrialComponentName=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: sm.delete_trial_component(TrialComponentName=name))
    return {"name": name, "arn": resp["TrialComponentArn"]}


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, reason=""):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    raise TimeoutError(f"timed out after {timeout_s}s waiting for: {reason or 'predicate'}; last result: {result}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
