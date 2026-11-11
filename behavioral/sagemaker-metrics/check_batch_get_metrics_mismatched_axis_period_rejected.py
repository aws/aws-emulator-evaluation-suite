"""batch-get-metrics-mismatched-axis-period-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-get-metrics-mismatched-axis-period-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """In one BatchGetMetrics request, a query pairing XAxisType=Timestamp with Period=IterationNumber
    resolves to Status=ValidationError, while the valid IterationNumber pairing for the same metric
    resolves to Complete with the written value 6.0."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())

    put_resp = metrics.batch_put_metrics(
        TrialComponentName=tc["name"],
        MetricData=[{"MetricName": "paired", "Timestamp": now, "Step": 0, "Value": 6.0}],
    )
    assert not put_resp.get("Errors"), (
        f"expected no per-item errors ingesting the metric, got {put_resp.get('Errors')}"
    )

    valid_query = {
        "MetricName": "paired",
        "ResourceArn": tc["arn"],
        "MetricStat": "Last",
        "Period": "IterationNumber",
        "XAxisType": "IterationNumber",
    }
    # Timestamp axis paired with the iteration-based Period is an invalid combination.
    invalid_query = dict(valid_query, XAxisType="Timestamp", Start=now - 120, End=now + 120)

    results = _poll_until(
        lambda: metrics.batch_get_metrics(MetricQueries=[valid_query, invalid_query])[
            "MetricQueryResults"
        ],
        lambda rs: rs[0]["Status"] == "Complete" and rs[0]["MetricValues"],
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert results[0]["Status"] == "Complete", (
        f"expected Status=Complete for the valid IterationNumber pairing, got {results[0]['Status']!r}"
    )
    assert abs(results[0]["MetricValues"][0] - 6.0) < 1e-6, (
        f"expected the valid pairing's value == 6.0, got {results[0]['MetricValues'][0]}"
    )
    assert results[1]["Status"] == "ValidationError", (
        f"expected Status=ValidationError for the Timestamp/IterationNumber mismatch, "
        f"got {results[1]['Status']!r}"
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
