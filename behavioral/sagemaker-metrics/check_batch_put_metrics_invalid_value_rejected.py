"""batch-put-metrics-invalid-value-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-put-metrics-invalid-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker-metrics"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A RawMetricData item with a non-finite (NaN) Value fails ingestion with
    INTERNAL_ERROR at its MetricIndex while a sibling valid item in the same batch
    still succeeds, and the rejected point is never queryable afterwards."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())

    put_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[
            {"MetricName": "ok-metric", "Timestamp": now, "Step": 0, "Value": 1.0},
            {"MetricName": "bad-metric", "Timestamp": now, "Step": 0, "Value": float("nan")},
        ],
    )
    errors = {e["MetricIndex"]: e["Code"] for e in put_resp.get("Errors", [])}
    assert errors.get(1) == "INTERNAL_ERROR", f"expected INTERNAL_ERROR at index 1, errors={errors!r}"
    assert 0 not in errors, f"valid item at index 0 was unexpectedly rejected: errors={errors!r}"

    # Positive control: the valid item in the same batch is genuinely persisted.
    ok_query = {
        "MetricName": "ok-metric",
        "ResourceArn": tc["arn"],
        "MetricStat": "Last",
        "Period": "IterationNumber",
        "XAxisType": "IterationNumber",
    }
    ok_result = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=[ok_query])["MetricQueryResults"][0],
        lambda r: r["Status"] == "Complete" and r["MetricValues"],
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert ok_result["Status"] == "Complete", f"expected Complete, got {ok_result['Status']!r}"
    assert abs(ok_result["MetricValues"][0] - 1.0) < 1e-6, (
        f"expected persisted ok-metric value 1.0, got {ok_result['MetricValues']!r}"
    )

    # Effect absent: the rejected point never became a known metric on this resource.
    bad_query = {
        "MetricName": "bad-metric",
        "ResourceArn": tc["arn"],
        "MetricStat": "Last",
        "Period": "IterationNumber",
        "XAxisType": "IterationNumber",
    }
    bad_result = metrics.batch_get_metrics(MetricQueries=[bad_query])["MetricQueryResults"][0]
    assert bad_result["Status"] == "Complete", f"expected Complete, got {bad_result['Status']!r}"
    assert bad_result["MetricValues"] == [], (
        f"expected no persisted values for rejected bad-metric, got {bad_result['MetricValues']!r}"
    )


def _create_trial_component(ctx):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-tc-")
    resp = sm.create_trial_component(
        TrialComponentName=name,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
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
    raise TimeoutError(f"condition not met within {timeout_s}s; last result={result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
