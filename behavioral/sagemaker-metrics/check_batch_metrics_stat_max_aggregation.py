"""batch-metrics-stat-max-aggregation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-metrics-stat-max-aggregation"
GROUP = "state"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Multiple raw values recorded at the same Step aggregate to their maximum when
    queried with MetricStat=Max on the IterationNumber axis."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())

    put_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[
            {"MetricName": "score", "Timestamp": now, "Step": 1, "Value": 3.0},
            {"MetricName": "score", "Timestamp": now + 1, "Step": 1, "Value": 9.0},
            {"MetricName": "score", "Timestamp": now + 2, "Step": 1, "Value": 5.0},
        ],
    )
    assert not put_resp.get("Errors"), f"batch_put_metrics reported errors: {put_resp.get('Errors')}"

    query = {
        "MetricName": "score",
        "ResourceArn": tc["arn"],
        "MetricStat": "Max",
        "Period": "IterationNumber",
        "XAxisType": "IterationNumber",
    }
    result = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=[query])["MetricQueryResults"][0],
        lambda r: r["Status"] == "Complete" and r["MetricValues"],
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert result["Status"] == "Complete", f"expected query status Complete, got {result['Status']!r}"
    assert len(result["MetricValues"]) == 1, (
        f"expected exactly 1 aggregated point for Step 1, got {len(result['MetricValues'])}: "
        f"{result['MetricValues']}"
    )
    assert round(result["XAxisValues"][0]) == 1, (
        f"expected XAxisValue (Step) 1, got {result['XAxisValues'][0]!r}"
    )
    assert abs(result["MetricValues"][0] - 9.0) < 1e-6, (
        f"MetricStat=Max must return the greatest raw value (9.0); got {result['MetricValues'][0]!r}"
    )


def _create_trial_component(ctx):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-tc-")
    resp = sm.create_trial_component(
        TrialComponentName=name,
        Tags=[{"Key": "sim2real", "Value": "batch-metrics-stat-max-aggregation"}],
    )
    ctx.on_cleanup(lambda: sm.delete_trial_component(TrialComponentName=name))
    return {"name": name, "arn": resp["TrialComponentArn"]}


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
