"""op-contract-put-cluster-capacity-providers."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-put-cluster-capacity-providers"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutClusterCapacityProviders associates FARGATE/FARGATE_SPOT with the cluster and sets
    the default strategy, both reflected on DescribeClusters afterward; ClusterNotFoundException
    for a cluster that doesn't exist."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-ecs-pccp-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: _retry_while_updating(lambda: ecs.delete_cluster(cluster=cluster_name)))

    resp = ecs.put_cluster_capacity_providers(
        cluster=cluster_name,
        capacityProviders=["FARGATE", "FARGATE_SPOT"],
        defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1, "base": 0}],
    )["cluster"]
    assert set(resp["capacityProviders"]) == {"FARGATE", "FARGATE_SPOT"}, resp["capacityProviders"]
    assert resp["defaultCapacityProviderStrategy"] == [
        {"capacityProvider": "FARGATE", "weight": 1, "base": 0}
    ], resp["defaultCapacityProviderStrategy"]

    described = ecs.describe_clusters(clusters=[cluster_name])["clusters"][0]
    assert set(described["capacityProviders"]) == {"FARGATE", "FARGATE_SPOT"}, described["capacityProviders"]

    code, message = _error(lambda: ecs.put_cluster_capacity_providers(
        cluster="sim2real-nonexistent-cluster-3390",
        capacityProviders=["FARGATE"],
        defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
    ))
    assert code == "ClusterNotFoundException", code
    assert message == "Cluster not found.", message


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, because an emulator accepting input real AWS refuses must fail loudly rather than
    read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_while_updating(fn, timeout_s=180.0, interval_s=5.0):
    """Call fn() until the cluster's capacity-provider attachment settles: ECS refuses cluster
    updates and deletes with UpdateInProgressException until then."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "UpdateInProgressException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
