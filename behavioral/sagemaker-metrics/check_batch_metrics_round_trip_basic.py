"""batch-metrics-round-trip-basic."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-metrics-round-trip-basic"
GROUP = "state"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A metric written with BatchPutMetrics reads back on the IterationNumber axis as exactly one value
    3.5 at Step 0 (MetricStat=Last), and a Timestamp-axis query for it resolves to Complete."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())

    put_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[{"MetricName": "loss", "Timestamp": now, "Step": 0, "Value": 3.5}],
    )
    assert not put_resp.get("Errors"), f"expected no per-item errors, got {put_resp.get('Errors')}"

    iter_query = {
        "MetricName": "loss",
        "ResourceArn": tc["arn"],
        "MetricStat": "Last",
        "Period": "IterationNumber",
        "XAxisType": "IterationNumber",
    }
    result = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=[iter_query])["MetricQueryResults"][0],
        lambda r: r["Status"] == "Complete" and r["MetricValues"],
        timeout_s=90.0,
        interval_s=3.0,
        reason="loss metric to become queryable on the IterationNumber axis",
    )
    assert result["Status"] == "Complete", f"expected Status=Complete, got {result['Status']}"
    assert len(result["MetricValues"]) == 1, f"expected exactly 1 value, got {result['MetricValues']}"
    assert abs(result["MetricValues"][0] - 3.5) < 1e-6, f"expected 3.5, got {result['MetricValues'][0]}"
    assert round(result["XAxisValues"][0]) == 0, f"expected Step 0, got {result['XAxisValues'][0]}"

    ts_query = {
        "MetricName": "loss",
        "ResourceArn": tc["arn"],
        "MetricStat": "Last",
        "Period": "OneMinute",
        "XAxisType": "Timestamp",
        "Start": now - 3600,
        "End": now + 3600,
    }
    ts_result = metrics.batch_get_metrics(MetricQueries=[ts_query])["MetricQueryResults"][0]
    assert ts_result["Status"] == "Complete", f"valid Timestamp-axis query on an existing metric should not error: {ts_result}"


def _create_trial_component(ctx):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-tc-")
    resp = sm.create_trial_component(
        TrialComponentName=name,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
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
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason}; last observed: {result}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
