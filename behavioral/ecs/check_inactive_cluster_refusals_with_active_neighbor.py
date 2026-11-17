"""inactive-cluster-refusals-with-active-neighbor."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "inactive-cluster-refusals-with-active-neighbor"
GROUP = "cluster-lifecycle"
SERVICES = ["ecs"]

_NOT_ACTIVE = ("ClientException", "Cluster was not ACTIVE.")
_TAG_INACTIVE = (
    "InvalidParameterException",
    "The specified cluster is inactive. Specify an active cluster and try again.",
)


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got = _error(fn)
    assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"


def _cluster_arns(ecs) -> set[str]:
    return {
        arn
        for page in ecs.get_paginator("list_clusters").paginate()
        for arn in page["clusterArns"]
    }


def _delete_cluster_once_settled(ecs, name: str, *, timeout_s: float = 60.0) -> None:
    """Delete ``name``, retrying only while its capacity-provider attachment is
    still converging after PutClusterCapacityProviders (UpdateInProgressException)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "UpdateInProgressException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An INACTIVE cluster is refused PutClusterCapacityProviders and TagResource, keeps no
    attached provider and drops from ListClusters, while a sibling ACTIVE cluster accepts
    the same PutClusterCapacityProviders call and reads the provider back."""
    ecs = ctx.client("ecs")

    dead_name = ctx.unique_name("sim2real-behav-ecs-dead-")
    ecs.create_cluster(clusterName=dead_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=dead_name))

    live_name = ctx.unique_name("sim2real-behav-ecs-live-")
    live = ecs.create_cluster(
        clusterName=live_name, tags=[{"key": "sim2real", "value": "true"}],
    )["cluster"]
    ctx.on_cleanup(lambda: _delete_cluster_once_settled(ecs, live_name))

    deleted = ecs.delete_cluster(cluster=dead_name)["cluster"]
    assert deleted["status"] == "INACTIVE", f"expected INACTIVE, got {deleted['status']!r}"
    dead_arn = deleted["clusterArn"]

    described = ecs.describe_clusters(clusters=[dead_name])["clusters"]
    assert described, f"expected DescribeClusters to still surface {dead_name!r}"
    assert described[0]["status"] == "INACTIVE", (
        f"independent read expected INACTIVE, got {described[0]['status']!r}"
    )
    assert described[0]["capacityProviders"] == [], (
        f"expected no capacity provider on the untouched INACTIVE cluster, "
        f"got {described[0]['capacityProviders']!r}"
    )

    expect_error(
        lambda: ecs.put_cluster_capacity_providers(
            cluster=dead_name, capacityProviders=["FARGATE"],
            defaultCapacityProviderStrategy=[],
        ),
        *_NOT_ACTIVE,
    )
    after_refusal = ecs.describe_clusters(clusters=[dead_name])["clusters"][0]
    assert after_refusal["capacityProviders"] == [], (
        f"refused PutClusterCapacityProviders must not attach a provider, "
        f"got {after_refusal['capacityProviders']!r}"
    )

    expect_error(
        lambda: ecs.tag_resource(
            resourceArn=dead_arn, tags=[{"key": "sim2real-probe", "value": "dead"}],
        ),
        *_TAG_INACTIVE,
    )

    deadline = time.monotonic() + 30
    while True:
        arns = _cluster_arns(ecs)
        if dead_arn not in arns:
            break
        if time.monotonic() >= deadline:
            raise AssertionError("INACTIVE cluster still in ListClusters after 30s")
        time.sleep(2)
    assert live["clusterArn"] in _cluster_arns(ecs), (
        "the ACTIVE sibling cluster is missing from ListClusters"
    )

    updated_live = ecs.put_cluster_capacity_providers(
        cluster=live_name, capacityProviders=["FARGATE"],
        defaultCapacityProviderStrategy=[],
    )["cluster"]
    assert updated_live["capacityProviders"] == ["FARGATE"], (
        f"expected PutClusterCapacityProviders response to carry FARGATE, "
        f"got {updated_live['capacityProviders']!r}"
    )

    read_back = ecs.describe_clusters(clusters=[live_name])["clusters"][0]
    assert read_back["capacityProviders"] == ["FARGATE"], (
        f"expected an independent DescribeClusters read to show FARGATE attached, "
        f"got {read_back['capacityProviders']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
