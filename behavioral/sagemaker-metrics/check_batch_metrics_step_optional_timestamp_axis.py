"""batch-metrics-step-optional-timestamp-axis."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-metrics-step-optional-timestamp-axis"
GROUP = "state"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A RawMetricData item without Step is accepted, but the IterationNumber axis returns Complete with
    no values for it, while a point with Step=0 for the same metric reads back as 9.5."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())

    put_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[
            {"MetricName": "no-step", "Timestamp": now, "Value": 5.5},
            {"MetricName": "with-step", "Timestamp": now, "Step": 0, "Value": 9.5},
        ],
    )
    assert not put_resp.get("Errors"), f"omitting Step should not produce a per-item error: {put_resp}"

    def _iter_query(metric_name):
        return {
            "MetricName": metric_name,
            "ResourceArn": tc["arn"],
            "MetricStat": "Last",
            "Period": "IterationNumber",
            "XAxisType": "IterationNumber",
        }

    # Positive control: the Step-carrying point is retrievable on the IterationNumber axis, so the
    # no-step assertion below cannot pass merely because nothing is ever retrievable.
    control_iter = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=[_iter_query("with-step")])["MetricQueryResults"][0],
        lambda r: r["Status"] == "Complete" and r["MetricValues"],
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert control_iter["Status"] == "Complete" and len(control_iter["MetricValues"]) == 1, (
        f"positive control (Step=0) should be retrievable on the IterationNumber axis: {control_iter}"
    )
    assert abs(control_iter["MetricValues"][0] - 9.5) < 1e-6, f"positive control value mismatch: {control_iter}"

    # The Step-omitted point: accepted at write time, but absent -- not erroring --
    # on the IterationNumber axis, because there is no Step to place it at.
    iter_result = metrics.batch_get_metrics(MetricQueries=[_iter_query("no-step")])["MetricQueryResults"][0]
    assert iter_result["Status"] == "Complete", f"unexpected status for step-omitted metric on IterationNumber axis: {iter_result}"
    assert iter_result["MetricValues"] == [], f"a Step-omitted point should not be placeable on the IterationNumber axis: {iter_result}"


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
