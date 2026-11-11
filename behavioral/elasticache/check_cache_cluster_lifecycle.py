"""cache-cluster-lifecycle."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

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

def _wait_deleted(fn, list_key, id_field, id_value, timeout_s=1800, interval_s=15, **extra):
    return _poll(
        lambda: _describe_one(fn, list_key, id_field, id_value, **extra),
        lambda item: item is None,
        timeout_s, interval_s,
    )

def _describe_cluster(ec, cluster_id):
    return _describe_one(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id)

def _wait_cluster_status(ec, cluster_id, status, timeout_s=1800, interval_s=15):
    return _wait_status(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id, "CacheClusterStatus", status, timeout_s, interval_s)

def _wait_cluster_deleted(ec, cluster_id, timeout_s=1800, interval_s=15):
    return _wait_deleted(ec.describe_cache_clusters, "CacheClusters", "CacheClusterId", cluster_id, timeout_s, interval_s)

# The harness's per-check budget for this suite: every wait ends only where the runner would
# stop the check anyway, so no wait is an assertion on elapsed time.
_SUITE_BUDGET_S = 3600

_VPC_CIDR = "10.234.0.0/16"
_SUBNET_CIDR = "10.234.1.0/24"

CHECK = "cache-cluster-lifecycle"
GROUP = 'cache-cluster'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cache cluster reaches available, honours ModifyCacheCluster, then ends gone, unlisted and unusable."""
    ec = ctx.client("elasticache")
    subnet_group = _make_cache_subnet_group(ctx, "sim2real-behav-ecc-")
    cluster_id = ctx.unique_name("sim2real-behav-ecc-")
    created = ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["CacheCluster"]
    ctx.on_cleanup(lambda: _delete_cluster_and_wait_gone(ec, cluster_id))
    assert created["CacheClusterId"] == cluster_id, f"create answered for {created['CacheClusterId']!r}"

    cluster = _wait_cluster_status(ec, cluster_id, "available", timeout_s=_SUITE_BUDGET_S)
    assert cluster is not None, "cluster never reached available"
    assert cluster["CacheClusterId"] == cluster_id, f"expected id {cluster_id}, got {cluster['CacheClusterId']}"
    assert cluster["Engine"] == "redis", f"expected engine redis, got {cluster['Engine']}"
    assert cluster["NumCacheNodes"] == 1, f"expected 1 node, got {cluster['NumCacheNodes']}"
    assert cluster["CacheNodeType"] == "cache.t3.micro", f"expected cache.t3.micro, got {cluster['CacheNodeType']}"

    # ShowCacheNodeInfo must materialise per-node detail once available.
    detailed = ec.describe_cache_clusters(
        CacheClusterId=cluster_id, ShowCacheNodeInfo=True,
    )["CacheClusters"][0]
    nodes = detailed.get("CacheNodes", [])
    assert len(nodes) == 1, f"expected 1 entry in CacheNodes, got {len(nodes)}: {nodes!r}"
    assert nodes[0]["CacheNodeStatus"] == "available", (
        f"expected CacheNodeStatus 'available', got {nodes[0].get('CacheNodeStatus')!r}"
    )

    new_window = "sun:23:00-mon:00:30"
    ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        PreferredMaintenanceWindow=new_window,
        ApplyImmediately=True,
    )
    _poll(
        lambda: _describe_cluster(ec, cluster_id),
        lambda c: c is not None and c.get("PreferredMaintenanceWindow") == new_window,
        300, 10,
    )

    ec.delete_cache_cluster(CacheClusterId=cluster_id)
    _wait_cluster_deleted(ec, cluster_id, timeout_s=_SUITE_BUDGET_S)

    # Gone beat 1: the read by id is refused with the specific not-found code.
    code, status, message = _error(lambda: ec.describe_cache_clusters(CacheClusterId=cluster_id))
    assert code == "CacheClusterNotFound", f"expected CacheClusterNotFound for the deleted cluster, got {code}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx describing the deleted cluster, got {status}"
    expected_message = f"CacheCluster not found: {cluster_id}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    # Gone beat 2: the paginated listing no longer holds it.
    listed = [
        c["CacheClusterId"]
        for page in ec.get_paginator("describe_cache_clusters").paginate()
        for c in page["CacheClusters"]
    ]
    assert cluster_id not in listed, "the deleted cache cluster is still listed by DescribeCacheClusters"
    # Gone beat 3: a mutation on the dead id is refused the same way.
    code, status, message = _error(
        lambda: ec.modify_cache_cluster(
            CacheClusterId=cluster_id, PreferredMaintenanceWindow=new_window, ApplyImmediately=True
        )
    )
    assert code == "CacheClusterNotFound", f"expected CacheClusterNotFound modifying the deleted cluster, got {code}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx modifying the deleted cluster, got {status}"
    expected_message = f"CacheCluster not found: {cluster_id}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, HTTP status, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message") or "",
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
