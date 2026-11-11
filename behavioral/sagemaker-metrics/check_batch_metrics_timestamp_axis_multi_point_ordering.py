"""batch-metrics-timestamp-axis-multi-point-ordering."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-metrics-timestamp-axis-multi-point-ordering"
GROUP = "state"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Points at Steps 0, 1 and 2 written out of order in separate BatchPutMetrics calls come back on
    the IterationNumber axis in ascending step order with the values 10.0, 20.0 and 30.0 aligned."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())
    # Write step=2 first, then step=0, then step=1: deliberately out of order.
    writes = [(2, 30.0), (0, 10.0), (1, 20.0)]

    for step, value in writes:
        put_resp = metrics.batch_put_metrics(
            TrialComponentName=tc["name"],
            MetricData=[{"MetricName": "throughput", "Timestamp": now + step, "Step": step, "Value": value}],
        )
        assert not put_resp.get("Errors"), f"unexpected per-item error writing step {step}: {put_resp.get('Errors')}"

    query = {
        "MetricName": "throughput",
        "ResourceArn": tc["arn"],
        "MetricStat": "Last",
        "Period": "IterationNumber",
        "XAxisType": "IterationNumber",
    }
    result = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=[query])["MetricQueryResults"][0],
        lambda r: r["Status"] == "Complete" and len(r["MetricValues"]) >= 3,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert result["Status"] == "Complete", f"expected query Status=Complete, got {result['Status']!r}"
    x_axis = result["XAxisValues"]
    m_values = result["MetricValues"]
    assert x_axis == sorted(x_axis), f"expected ascending XAxisValues, got {x_axis}"
    assert [round(x) for x in x_axis] == [0, 1, 2], (
        f"expected steps [0, 1, 2] regardless of write order, got {[round(x) for x in x_axis]}"
    )
    assert m_values == [10.0, 20.0, 30.0], (
        f"expected values aligned to their step [10.0, 20.0, 30.0], got {m_values}"
    )


def _create_trial_component(ctx):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-tc-")
    resp = sm.create_trial_component(
        TrialComponentName=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
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
    raise AssertionError(f"timed out after {timeout_s}s waiting for predicate; last result: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
