"""batch-metrics-training-loop-e2e."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-metrics-training-loop-e2e"
GROUP = "e2e"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Loss and accuracy series written across five BatchPutMetrics calls read back in one
    BatchGetMetrics request with Last, Min, Max, Avg and Count equal to the written history, and Avg
    over several raw values at one step equals their arithmetic mean."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())

    # Simulate 5 checkpoints of a training job, each emitting loss+accuracy,
    # each checkpoint ingested via its own BatchPutMetrics call (as a real job would).
    loss_values = [0.9, 0.7, 0.5, 0.4, 0.35]
    acc_values = [0.10, 0.40, 0.60, 0.75, 0.82]
    for step, (loss, acc) in enumerate(zip(loss_values, acc_values)):
        put_resp = metrics.batch_put_metrics(
            TrialComponentName=tc["name"],
            MetricData=[
                {"MetricName": "loss", "Timestamp": now + step, "Step": step, "Value": loss},
                {"MetricName": "accuracy", "Timestamp": now + step, "Step": step, "Value": acc},
            ],
        )
        assert not put_resp.get("Errors"), (
            f"expected no per-item errors ingesting checkpoint {step}, got {put_resp.get('Errors')}"
        )

    # A later, separate BatchPutMetrics call adds 3 raw same-step samples for a third
    # metric, to exercise Avg aggregation as part of the same end-to-end pipeline.
    raw_values = [3.0, 9.0, 5.0]
    expected_avg = sum(raw_values) / len(raw_values)
    put_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[
            {"MetricName": "score", "Timestamp": now + 100 + i, "Step": 1, "Value": v}
            for i, v in enumerate(raw_values)
        ],
    )
    assert not put_resp.get("Errors"), (
        f"expected no per-item errors ingesting the score samples, got {put_resp.get('Errors')}"
    )

    def make_query(name, stat):
        return {
            "MetricName": name,
            "ResourceArn": tc["arn"],
            "MetricStat": stat,
            "Period": "IterationNumber",
            "XAxisType": "IterationNumber",
        }

    queries = [
        make_query("loss", "Last"),
        make_query("loss", "Min"),
        make_query("loss", "Max"),
        make_query("accuracy", "Avg"),
        make_query("accuracy", "Count"),
        make_query("score", "Avg"),
    ]
    results = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=queries)["MetricQueryResults"],
        lambda rs: all(r["Status"] == "Complete" and r["MetricValues"] for r in rs),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert len(results) == 6, f"expected 6 MetricQueryResults, got {len(results)}"
    loss_last, loss_min, loss_max, acc_avg, acc_count, score_avg = results

    # Each of loss/accuracy has exactly one raw sample per step, so per-step
    # Last/Min/Max/Avg/Count all trivially pass through / count that one sample --
    # true cross-sample aggregation only kicks in within a shared step (see "score").
    assert loss_last["Status"] == "Complete", f"expected Status=Complete, got {loss_last['Status']!r}"
    assert len(loss_last["MetricValues"]) == len(loss_values), (
        f"expected {len(loss_values)} loss/Last points, got {len(loss_last['MetricValues'])}"
    )
    assert loss_last["MetricValues"] == loss_values, (
        f"expected loss/Last == {loss_values}, got {loss_last['MetricValues']}"
    )
    assert loss_min["MetricValues"] == loss_values, (
        f"expected loss/Min == {loss_values}, got {loss_min['MetricValues']}"
    )
    assert loss_max["MetricValues"] == loss_values, (
        f"expected loss/Max == {loss_values}, got {loss_max['MetricValues']}"
    )

    assert len(acc_avg["MetricValues"]) == len(acc_values), (
        f"expected {len(acc_values)} accuracy/Avg points, got {len(acc_avg['MetricValues'])}"
    )
    assert acc_avg["MetricValues"] == acc_values, (
        f"expected accuracy/Avg == {acc_values}, got {acc_avg['MetricValues']}"
    )
    assert len(acc_count["MetricValues"]) == len(acc_values), (
        f"expected {len(acc_values)} accuracy/Count points, got {len(acc_count['MetricValues'])}"
    )
    assert all(round(c) == 1 for c in acc_count["MetricValues"]), (
        f"each step has exactly one accuracy sample: {acc_count['MetricValues']}"
    )

    # "score" has 3 raw samples sharing a single step, so Avg genuinely aggregates.
    assert score_avg["Status"] == "Complete", f"expected Status=Complete, got {score_avg['Status']!r}"
    assert len(score_avg["MetricValues"]) == 1, (
        f"expected 1 score/Avg point, got {len(score_avg['MetricValues'])}"
    )
    assert round(score_avg["XAxisValues"][0]) == 1, (
        f"expected score/Avg step 1, got {score_avg['XAxisValues'][0]}"
    )
    assert abs(score_avg["MetricValues"][0] - expected_avg) < 1e-3, (
        f"expected score/Avg == mean{raw_values} = {expected_avg}, got {score_avg['MetricValues'][0]}"
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
