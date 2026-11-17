"""put-cluster-capacity-providers-duplicate-name-in-list-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-cluster-capacity-providers-duplicate-name-in-list-rejected"
GROUP = 'error-semantics'
SERVICES = ['ecs']


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED with {result!r}")


def _delete_cluster_retrying(ecs, cluster_name, *, timeout_s=90, interval_s=5):
    """DeleteCluster while a prior capacity-provider association is still settling answers
    UpdateInProgressException; retry on that code only, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "UpdateInProgressException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutClusterCapacityProviders refuses a capacityProviders list that names the built-in
    FARGATE provider twice as though it named an unknown provider, leaving the cluster with
    none associated, and the identical list with the name listed once then succeeds."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-ecs-pccpdup-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: _delete_cluster_retrying(ecs, cluster_name))

    baseline = ecs.describe_clusters(clusters=[cluster_name])["clusters"][0]
    assert baseline.get("capacityProviders", []) == [], (
        f"a freshly created cluster already has capacity providers: {baseline.get('capacityProviders')!r}"
    )

    # --- negative: the same provider named twice is refused outright ---
    error = _error(
        lambda: ecs.put_cluster_capacity_providers(
            cluster=cluster_name,
            capacityProviders=["FARGATE", "FARGATE"],
            defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
        )
    )
    expected = (
        "InvalidParameterException",
        "The specified capacity provider was not found. Specify a valid capacity provider and try again.",
    )
    assert error == expected, (
        f"PutClusterCapacityProviders with a duplicated name: expected {expected!r}, got {error!r}"
    )

    # --- the rejected call left the cluster with no capacity providers associated ---
    after_reject = ecs.describe_clusters(clusters=[cluster_name])["clusters"][0]
    assert after_reject.get("capacityProviders", []) == [], (
        f"a rejected PutClusterCapacityProviders associated something anyway: "
        f"{after_reject.get('capacityProviders')!r}"
    )

    # --- positive control: the identical list with the name listed once succeeds ---
    ecs.put_cluster_capacity_providers(
        cluster=cluster_name,
        capacityProviders=["FARGATE"],
        defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
    )
    control = ecs.describe_clusters(clusters=[cluster_name])["clusters"][0]
    assert control.get("capacityProviders") == ["FARGATE"], (
        f"positive control: expected ['FARGATE'] associated, got {control.get('capacityProviders')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
