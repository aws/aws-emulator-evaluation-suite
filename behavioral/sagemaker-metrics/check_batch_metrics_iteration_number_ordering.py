"""batch-metrics-iteration-number-ordering."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-metrics-iteration-number-ordering"
GROUP = "state"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Metrics written out of Step order in one BatchPutMetrics call come back from BatchGetMetrics on
    the IterationNumber axis in ascending step order with each value aligned to its step."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())
    steps = [0, 1, 2, 3, 4]
    values = [0.0, 10.0, 20.0, 30.0, 40.0]
    write_order = [3, 1, 4, 0, 2]  # deliberately not ascending by Step

    put_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[
            {"MetricName": "acc", "Timestamp": now + steps[i], "Step": steps[i], "Value": values[i]}
            for i in write_order
        ],
    )
    assert not put_resp.get("Errors")

    query = {
        "MetricName": "acc",
        "ResourceArn": tc["arn"],
        "MetricStat": "Last",
        "Period": "IterationNumber",
        "XAxisType": "IterationNumber",
    }
    result = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=[query])["MetricQueryResults"][0],
        lambda r: r["Status"] == "Complete" and len(r["MetricValues"]) >= len(steps),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert result["Status"] == "Complete"
    x_axis = result["XAxisValues"]
    m_values = result["MetricValues"]
    assert x_axis == sorted(x_axis)
    assert [round(x) for x in x_axis] == steps
    assert m_values == values


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
    raise TimeoutError(f"poll did not satisfy predicate within {timeout_s}s; last result: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
