"""batch-metrics-stat-min-aggregation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-metrics-stat-min-aggregation"
GROUP = "state"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Multiple raw values recorded at the same Step aggregate to their minimum when
    queried with MetricStat=Min on the IterationNumber axis."""
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
    assert not put_resp.get("Errors"), f"expected no put errors, got {put_resp.get('Errors')}"

    query = {
        "MetricName": "score",
        "ResourceArn": tc["arn"],
        "MetricStat": "Min",
        "Period": "IterationNumber",
        "XAxisType": "IterationNumber",
    }
    result = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=[query])["MetricQueryResults"][0],
        lambda r: r["Status"] == "Complete" and r["MetricValues"],
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert result["Status"] == "Complete", f"expected Complete, got {result['Status']!r}"
    assert len(result["MetricValues"]) == 1, (
        f"expected 1 aggregated point, got {len(result['MetricValues'])}: {result['MetricValues']}"
    )
    assert round(result["XAxisValues"][0]) == 1, (
        f"expected Step 1 on the IterationNumber axis, got {result['XAxisValues'][0]!r}"
    )
    assert abs(result["MetricValues"][0] - 3.0) < 1e-6, (
        f"expected Min aggregation of [3.0, 9.0, 5.0] == 3.0, got {result['MetricValues'][0]!r}"
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
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
