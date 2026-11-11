"""cache-cluster-duplicate-id."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the botocore Error (Code, Message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _describe_one(fn, list_key, id_field, id_value, **extra):
    """describe wrapper: return the single item, None on NotFound / empty list."""
    try:
        resp = fn(**{id_field: id_value}, **extra)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code") or ""
        if "NotFound" in code:
            return None
        raise
    items = resp.get(list_key, [])
    return items[0] if items else None

def _poll(probe, predicate, timeout_s=600, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)

def _wait_status(fn, list_key, id_field, id_value, status_field, target, timeout_s=1800, interval_s=15, **extra):
    return _poll(
        lambda: _describe_one(fn, list_key, id_field, id_value, **extra),
        lambda item: item is not None and item.get(status_field) == target,
        timeout_s, interval_s,
    )

def _wait_cluster_status(ec, cluster_id, status, timeout_s=1800, interval_s=15):
    return _wait_status(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id, "CacheClusterStatus", status, timeout_s, interval_s)

_VPC_CIDR = "10.234.0.0/16"
_SUBNET_CIDR = "10.234.1.0/24"

CHECK = "cache-cluster-duplicate-id"
GROUP = 'cache-cluster'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a cluster with an already-used CacheClusterId is rejected once the id is taken."""
    ec = ctx.client("elasticache")
    subnet_group = _make_cache_subnet_group(ctx, "sim2real-behav-ecc-dup-")
    cluster_id = ctx.unique_name("sim2real-behav-ecc-dup-")
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait_gone(ec, cluster_id))

    # The id is reserved immediately — while still 'creating', not only once available.
    refused = _error(
        lambda: ec.create_cache_cluster(
            CacheClusterId=cluster_id,
            Engine="redis",
            CacheNodeType="cache.t3.micro",
            NumCacheNodes=1,
            CacheSubnetGroupName=subnet_group,
        ),
    )
    assert refused == (
        "CacheClusterAlreadyExists",
        "Cache cluster already exists",
    ), f"expected CacheClusterAlreadyExists with its exact message, got {refused!r}"

    # Cannot delete a cluster that is still creating. The create above holds the creating
    # window for minutes; the refusal message names the state the cluster was in.
    refused = _error(lambda: ec.delete_cache_cluster(CacheClusterId=cluster_id))
    assert refused == (
        "InvalidCacheClusterState",
        "Can only delete cache clusters with state in: available, failed, "
        "incompatible-parameters, incompatible-network, restore-failed, recovering. "
        f"Cluster {cluster_id} has state: creating.",
    ), f"expected InvalidCacheClusterState with its exact message, got {refused!r}"

    _wait_cluster_status(ec, cluster_id, "available", timeout_s=1500)
    ec.delete_cache_cluster(CacheClusterId=cluster_id)

    # The delete must be observable at an independent read: the cluster is deleting right after
    # the call, then drains to gone.
    deleting = _describe_one(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id)
    assert deleting is not None and deleting["CacheClusterStatus"] == "deleting", deleting
    _poll(
        lambda: _describe_one(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id),
        lambda item: item is None,
        timeout_s=900,
    )
    gone = _describe_one(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id)
    assert gone is None, f"expected {cluster_id} gone, still describes as {gone!r}"
    refused = _error(lambda: ec.delete_cache_cluster(CacheClusterId=cluster_id))
    assert refused == (
        "CacheClusterNotFound",
        f"CacheCluster not found: {cluster_id}",
    ), f"expected CacheClusterNotFound with its exact message, got {refused!r}"


def _delete_cluster_and_wait_gone(ec, cluster_id, timeout_s=1200.0):
    """Delete the cluster (tolerating one already deleting or gone) and wait until it is gone,
    so the subnet group registered before it can be deleted after it."""
    try:
        ec.delete_cache_cluster(CacheClusterId=cluster_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "CacheClusterNotFound":
            return
        if code != "InvalidCacheClusterState":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            clusters = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "CacheClusterNotFound":
                return
            raise
        if not clusters:
            return
        if clusters[0]["CacheClusterStatus"] == "available":
            try:
                ec.delete_cache_cluster(CacheClusterId=cluster_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("CacheClusterNotFound", "InvalidCacheClusterState"):
                    raise
        time.sleep(15)


def _delete_ec2_quietly(fn, not_found_codes):
    try:
        fn()
    except ClientError as exc:
        if (exc.response.get("Error", {}).get("Code") or "") not in not_found_codes:
            raise


def _delete_subnet_group_quietly(ec, name):
    try:
        ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "CacheSubnetGroupNotFoundFault":
            raise


def _make_cache_subnet_group(ctx, prefix):
    """Create a throwaway VPC, one subnet and a cache subnet group over it.

    The cluster never lands in an ambient default VPC. Cleanups run last-in first-out: the
    cluster (registered after this returns) is gone before the group, subnet and VPC go.
    """
    ec2 = ctx.client("ec2")
    ec = ctx.client("elasticache")
    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name(prefix + "vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _delete_ec2_quietly(
            lambda: ec2.delete_vpc(VpcId=vpc_id), ("InvalidVpcID.NotFound",)
        )
    )
    az = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=_SUBNET_CIDR,
        AvailabilityZone=az,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name(prefix + "subnet-")}],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _delete_ec2_quietly(
            lambda: ec2.delete_subnet(SubnetId=subnet_id), ("InvalidSubnetID.NotFound",)
        )
    )
    group_name = ctx.unique_name(prefix + "sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=group_name,
        CacheSubnetGroupDescription="sim2real throwaway subnet group",
        SubnetIds=[subnet_id],
    )
    ctx.on_cleanup(lambda: _delete_subnet_group_quietly(ec, group_name))
    return group_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
