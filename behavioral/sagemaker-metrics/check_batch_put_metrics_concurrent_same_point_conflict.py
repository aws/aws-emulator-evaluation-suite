"""batch-put-metrics-concurrent-same-point-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "batch-put-metrics-concurrent-same-point-conflict"
GROUP = "concurrency"
SERVICES = ["sagemaker-metrics"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent BatchPutMetrics calls writing one metric point with different values: at least
    one is accepted, a rejected one reports only CONFLICT_ERROR, and the persisted value is an
    accepted writer's."""
    tc = _create_trial_component(ctx)
    metrics = ctx.client("sagemaker-metrics")
    now = int(time.time())
    n = 6
    metric_name = "race"
    step = 0
    submitted_values = [float(i) for i in range(n)]

    def racer(value):
        resp = metrics.batch_put_metrics(
            TrialComponentName=tc["name"],
            MetricData=[
                {"MetricName": metric_name, "Timestamp": now, "Step": step, "Value": value}
            ],
        )
        errors = resp.get("Errors", [])
        code = next((e["Code"] for e in errors if e["MetricIndex"] == 0), None)
        return code

    with ThreadPoolExecutor(max_workers=n) as pool:
        codes = list(pool.map(racer, submitted_values))

    accepted = [v for v, c in zip(submitted_values, codes) if c is None]
    failures = [c for c in codes if c is not None]
    assert accepted, f"at least one concurrent writer to the same point must be accepted (codes={codes})"
    # Overlapping writers may conflict; serialized writers are all accepted.
    for code in failures:
        assert code == "CONFLICT_ERROR", f"expected CONFLICT_ERROR, got {code!r} (codes={codes})"

    query = {
        "MetricName": metric_name,
        "ResourceArn": tc["arn"],
        "MetricStat": "Last",
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
        f"expected exactly one persisted value for the contested point, "
        f"got {result['MetricValues']!r}"
    )
    persisted = result["MetricValues"][0]
    assert any(abs(persisted - v) < 1e-6 for v in accepted), (
        f"persisted value {persisted} does not match any accepted racer value {accepted}"
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
