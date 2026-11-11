"""batch-metrics-stat-count-aggregation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-metrics-stat-count-aggregation"
GROUP = "state"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Multiple raw values recorded at the same Step aggregate to the number of raw
    points recorded when queried with MetricStat=Count on the IterationNumber axis."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())
    raw_values = [3.0, 9.0, 5.0]

    put_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[
            {"MetricName": "score", "Timestamp": now + i, "Step": 1, "Value": v}
            for i, v in enumerate(raw_values)
        ],
    )
    assert not put_resp.get("Errors"), f"batch_put_metrics reported errors: {put_resp.get('Errors')}"

    query = {
        "MetricName": "score",
        "ResourceArn": tc["arn"],
        "MetricStat": "Count",
        "Period": "IterationNumber",
        "XAxisType": "IterationNumber",
    }
    result = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=[query])["MetricQueryResults"][0],
        lambda r: r["Status"] == "Complete" and r["MetricValues"],
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert result["Status"] == "Complete", f"expected Status=Complete, got {result['Status']!r}"
    assert len(result["MetricValues"]) == 1, (
        f"expected exactly 1 aggregated point for the single shared Step, got {len(result['MetricValues'])}: {result}"
    )
    assert round(result["XAxisValues"][0]) == 1, (
        f"expected the IterationNumber axis value to be Step=1, got {result['XAxisValues'][0]}"
    )
    assert abs(result["MetricValues"][0] - len(raw_values)) < 1e-6, (
        f"MetricStat=Count over {len(raw_values)} raw points at Step=1 should equal {len(raw_values)}, "
        f"got {result['MetricValues'][0]}"
    )


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
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
