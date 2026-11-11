"""list-metrics-pagination-stable-order."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-metrics-pagination-stable-order"
GROUP = "ordering"
SERVICES = ["cloudwatch"]

_NUM_METRICS = 20


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListMetrics pagination across NextToken pages returns a stable, non-duplicating,
    non-skipping ordering of the full metric set for a fixed namespace."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-lm-")

    for i in range(_NUM_METRICS):
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": f"Metric{i:03d}",
                    "Dimensions": [{"Name": "sim2real-behav-batch", "Value": namespace}],
                    "Value": float(i),
                    "Unit": "Count",
                }
            ],
        )

    # ListMetrics has documented propagation latency (up to ~15 minutes); poll with a
    # bounded retry and fail rather than hang if the metrics never land.
    left = ctx.time_left()
    deadline = time.monotonic() + (6 * 60 if left is None else min(6 * 60, left))
    seen_count = 0
    while time.monotonic() < deadline:
        seen_count = len(_list_all_metrics(cw, namespace))
        if seen_count >= _NUM_METRICS:
            break
        time.sleep(2)
    if seen_count < _NUM_METRICS:
        raise AssertionError(
            f"only {seen_count}/{_NUM_METRICS} metrics visible via ListMetrics within timeout"
        )

    first_pass = _list_all_metrics(cw, namespace)
    second_pass = _list_all_metrics(cw, namespace)

    assert len(first_pass) == _NUM_METRICS, f"expected {_NUM_METRICS} metrics, got {len(first_pass)}"
    assert len(set(first_pass)) == len(first_pass), "duplicate metric identity within a single pagination sweep"
    assert first_pass == second_pass, "metric ordering was not stable across two independent full paginations"


# ===== helpers =====

def _list_all_metrics(cw, namespace: str) -> list[tuple]:
    identities: list[tuple] = []
    seen: set[tuple] = set()
    kwargs: dict = {"Namespace": namespace}
    while True:
        resp = cw.list_metrics(**kwargs)
        for m in resp.get("Metrics", []):
            dims = tuple(sorted((d["Name"], d["Value"]) for d in m.get("Dimensions", [])))
            identity = (m["Namespace"], m["MetricName"], dims)
            assert identity not in seen, f"duplicate metric seen while paginating: {identity}"
            seen.add(identity)
            identities.append(identity)
        next_token = resp.get("NextToken")
        if not next_token:
            break
        kwargs["NextToken"] = next_token
    return identities


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
