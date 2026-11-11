"""put-cluster-capacity-providers-invalid-base-weight-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-cluster-capacity-providers-invalid-base-weight-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutClusterCapacityProviders with base -1 in the default strategy fails with InvalidParameterException
    and its exact message, the cluster's default strategy stays empty, and a valid FARGATE strategy is
    accepted (client-side validation is off so the value reaches the service).
    """
    ecs = ctx.client("ecs")
    unvalidated = ctx.client("ecs", config=Config(parameter_validation=False))

    cluster_name = ctx.unique_name("sim2real-badcp-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name,
        tags=[{"key": "sim2real", "value": CHECK}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _retry_while_updating(lambda: ecs.delete_cluster(cluster=cluster_arn)))

    code, message = _error(
        lambda: unvalidated.put_cluster_capacity_providers(
            cluster=cluster_name,
            capacityProviders=["FARGATE"],
            defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1, "base": -1}],
        )
    )
    assert code == "InvalidParameterException", code
    assert message == (
        "The specified base value '-1' is invalid. Specify an integer between 0 and 100000 and try again."
    ), message

    # Effect absent: the cluster still has no default capacity provider strategy.
    described = ecs.describe_clusters(clusters=[cluster_arn])["clusters"][0]
    assert described.get("defaultCapacityProviderStrategy", []) == [], (
        f"a default capacity provider strategy leaked despite the rejected base value: "
        f"{described.get('defaultCapacityProviderStrategy')}"
    )

    # Positive control: a valid base/weight value succeeds.
    ecs.put_cluster_capacity_providers(
        cluster=cluster_name,
        capacityProviders=["FARGATE"],
        defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1, "base": 0}],
    )
    described = ecs.describe_clusters(clusters=[cluster_arn])["clusters"][0]
    strategy = described["defaultCapacityProviderStrategy"]
    assert len(strategy) == 1 and strategy[0]["capacityProvider"] == "FARGATE", (
        f"expected exactly one FARGATE strategy entry after the valid call, got {strategy!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, because an emulator accepting input real AWS refuses must fail loudly rather than
    read as an error-code mismatch."""
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
