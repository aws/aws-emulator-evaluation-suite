"""concurrent-put-cluster-capacity-providers-serializes."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-put-cluster-capacity-providers-serializes"
GROUP = "concurrency"
SERVICES = ["ecs"]

_CONFIG_A = {
    "capacityProviders": ["FARGATE"],
    "defaultCapacityProviderStrategy": [{"capacityProvider": "FARGATE", "weight": 1, "base": 0}],
}
_CONFIG_B = {
    "capacityProviders": ["FARGATE", "FARGATE_SPOT"],
    "defaultCapacityProviderStrategy": [{"capacityProvider": "FARGATE_SPOT", "weight": 1, "base": 0}],
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutClusterCapacityProviders calls against the same cluster serialize
    to one internally-consistent configuration rather than corrupting the cluster's
    capacity-provider / default-strategy association."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_arn))

    def _apply(config: dict[str, Any]) -> str | None:
        try:
            ecs.put_cluster_capacity_providers(cluster=cluster_arn, **config)
            return None
        except Exception as exc:  # noqa: BLE001
            return _error_code_from_exc(exc)

    configs = [_CONFIG_A if i % 2 == 0 else _CONFIG_B for i in range(10)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_apply, configs))

    successes = [r for r in results if r is None]
    failures = [r for r in results if r is not None]
    assert successes, f"expected at least one racer to succeed, got results={results}"
    bad_failures = [f for f in failures if f != "UpdateInProgressException"]
    assert not bad_failures, f"unexpected non-serialization error codes: {bad_failures}"

    # Poll until the cluster settles into one of the two known-good configurations.
    def _describe() -> dict[str, Any]:
        cluster = ecs.describe_clusters(clusters=[cluster_arn])["clusters"][0]
        return {
            "capacityProviders": sorted(cluster.get("capacityProviders", [])),
            "defaultCapacityProviderStrategy": cluster.get("defaultCapacityProviderStrategy", []),
        }

    def _is_consistent(state: dict[str, Any]) -> bool:
        cps = set(state["capacityProviders"])
        if cps == set(_CONFIG_A["capacityProviders"]) or cps == set(_CONFIG_B["capacityProviders"]):
            strategy_providers = {s["capacityProvider"] for s in state["defaultCapacityProviderStrategy"]}
            # Every capacity provider referenced by the default strategy must be one of
            # the associated capacity providers (no dangling / inconsistent reference).
            return strategy_providers.issubset(cps) and len(strategy_providers) > 0
        return False

    final_state = _poll_until(_describe, _is_consistent, timeout_s=30.0, interval_s=1.0)
    assert final_state["capacityProviders"] in (
        sorted(_CONFIG_A["capacityProviders"]),
        sorted(_CONFIG_B["capacityProviders"]),
    ), f"final cluster capacityProviders is neither racer's config: {final_state}"

    # Freeze check: once the race has settled, repeated independent reads must all
    # report the SAME state — a torn/oscillating result would mean the "winning"
    # config observed above was a transient snapshot, not the settled truth.
    observed = [_describe() for _ in range(3)]
    assert all(state == final_state for state in observed), (
        f"expected repeated DescribeClusters reads to report the same settled state "
        f"{final_state}, got {observed}"
    )


def _error_code_from_exc(exc: Exception) -> str:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code", type(exc).__name__)
    return type(exc).__name__


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _safe_delete_cluster(ctx, cluster_arn: str) -> None:
    """Detach the providers, then delete the cluster; an in-flight update is retried every 2 s to
    the deadline, a cluster already gone is fine, and any other failure raises."""
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + 60.0
    for call in (
        lambda: ecs.put_cluster_capacity_providers(
            cluster=cluster_arn, capacityProviders=[], defaultCapacityProviderStrategy=[]
        ),
        lambda: ecs.delete_cluster(cluster=cluster_arn),
    ):
        while True:
            try:
                call()
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ClusterNotFoundException":
                    return
                if code not in ("UpdateInProgressException", "ClusterContainsTasksException") or (
                    time.monotonic() >= deadline
                ):
                    raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
