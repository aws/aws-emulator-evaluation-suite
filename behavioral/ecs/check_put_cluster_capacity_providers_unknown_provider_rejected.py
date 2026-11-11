"""put-cluster-capacity-providers-unknown-provider-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-cluster-capacity-providers-unknown-provider-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutClusterCapacityProviders naming a nonexistent capacity provider fails with InvalidParameterException
    and its exact message, nothing is associated with the cluster, and the same call with FARGATE succeeds.
    """
    ecs = ctx.client("ecs")

    cluster_arn = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-cluster-"),
        tags=[{"key": "sim2real", "value": CHECK}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _retry_while_updating(lambda: ecs.delete_cluster(cluster=cluster_arn)))

    bogus_name = ctx.unique_name("sim2real-nonexistent-cp-")

    # Negative: reference a capacity provider name that was never created.
    code, message = _error(
        lambda: ecs.put_cluster_capacity_providers(
            cluster=cluster_arn,
            capacityProviders=[bogus_name],
            defaultCapacityProviderStrategy=[{"capacityProvider": bogus_name, "weight": 1}],
        )
    )
    assert code == "InvalidParameterException", (
        f"expected a client-side rejection for unknown capacity provider, got {code!r}"
    )
    assert message == (
        "The specified capacity provider was not found. Specify a valid capacity provider and try again."
    ), message

    # Effect absent: the cluster must not have picked up the bogus association.
    described = ecs.describe_clusters(clusters=[cluster_arn])["clusters"][0]
    assert described.get("capacityProviders", []) == [], (
        f"expected no capacity providers after the rejected call, "
        f"got {described.get('capacityProviders')!r}"
    )

    # Positive control: the built-in FARGATE capacity provider always exists and is
    # accepted, actually mutating the cluster's capacity provider association.
    ecs.put_cluster_capacity_providers(
        cluster=cluster_arn,
        capacityProviders=["FARGATE"],
        defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
    )

    def _detach() -> None:
        _retry_while_updating(
            lambda: ecs.put_cluster_capacity_providers(
                cluster=cluster_arn, capacityProviders=[], defaultCapacityProviderStrategy=[]
            )
        )

    ctx.on_cleanup(_detach)

    described2 = ecs.describe_clusters(clusters=[cluster_arn])["clusters"][0]
    assert "FARGATE" in described2.get("capacityProviders", []), (
        f"expected FARGATE to be associated after a valid call, "
        f"got {described2.get('capacityProviders')!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
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
