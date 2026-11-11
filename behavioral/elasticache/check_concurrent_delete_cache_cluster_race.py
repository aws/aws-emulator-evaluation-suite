"""concurrent-delete-cache-cluster-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-cache-cluster-race"
GROUP = "concurrency"
SERVICES = ["elasticache"]

_VPC_CIDR = "10.230.0.0/16"
_SUBNET_CIDR = "10.230.1.0/24"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent DeleteCacheCluster calls on the same cluster resolve deterministically:
    exactly one succeeds (transitions to 'deleting') and the other is rejected with
    InvalidCacheClusterState, with no double-delete artifact."""
    ec = ctx.client("elasticache")
    subnet_group = _make_cache_subnet_group(ctx, "sim2real-cdc-")
    cluster_id = ctx.unique_name("sim2real-cdc-")

    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="memcached",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait_gone(ec, cluster_id))

    _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=900)

    def _delete():
        return ec.delete_cache_cluster(CacheClusterId=cluster_id)

    outcomes = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_delete) for _ in range(2)]
        for fut in futures:
            try:
                resp = fut.result()
                outcomes.append(("ok", resp["CacheCluster"]["CacheClusterStatus"]))
            except ClientError as exc:
                err = exc.response["Error"]
                outcomes.append(("error", err.get("Code"), err.get("Message")))

    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "error"]
    assert len(successes) == 1, f"expected exactly one winner, got {outcomes}"
    assert len(failures) == 1, f"expected exactly one loser, got {outcomes}"
    assert successes[0][1] == "deleting", f"the winning delete must report deleting, got {successes}"
    assert failures[0][1] == "InvalidCacheClusterState", f"expected InvalidCacheClusterState, got {failures}"
    # message varies: the loser reads "...modified by a concurrent operation..." when it lands
    # inside the winner's state flip, and "Can only delete cache clusters with state in: ...
    # has state: deleting." when it lands after it; the code is the same either way, and the
    # stable part of whichever form arrived is graded.
    loser_message = failures[0][2] or ""
    assert "concurrent operation" in loser_message or loser_message.endswith(
        f"Cluster {cluster_id} has state: deleting."
    ), f"unexpected loser message {loser_message!r}"

    # Confirm the single accepted delete actually completes (no double-delete artifact
    # left behind, no orphaned cluster stuck in a state neither deleted nor available).
    deleted = _wait_for_cluster_gone(ctx, cluster_id, timeout_s=900)
    assert deleted, f"cluster {cluster_id} was never fully removed after the race"

    # A mutation on the now-dead id must also fail -- proves the cluster is not merely
    # invisible to describe but actually gone, and that the race left no resurrection path.
    third_code, third_message = _error(lambda: ec.delete_cache_cluster(CacheClusterId=cluster_id))
    assert third_code == "CacheClusterNotFound", (
        f"a delete on the already-gone cluster {cluster_id} must fail with "
        f"CacheClusterNotFound, got {third_code!r}"
    )
    expected = f"CacheCluster not found: {cluster_id}"
    assert third_message == expected, f"expected message {expected!r}, got {third_message!r}"


def _error(fn):
    """Call fn(); return the botocore Error (Code, Message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
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


def _wait_for_cluster_status(ctx, cluster_id, wanted_statuses, timeout_s=900.0, interval_s=15.0):
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = ec.describe_cache_clusters(CacheClusterId=cluster_id)
        clusters = resp.get("CacheClusters", [])
        if clusters:
            last_status = clusters[0]["CacheClusterStatus"]
            if last_status in wanted_statuses:
                return last_status
        time.sleep(interval_s)
    raise AssertionError(
        f"cluster {cluster_id} never reached {wanted_statuses}; last status={last_status}"
    )


def _wait_for_cluster_gone(ctx, cluster_id, timeout_s=900.0, interval_s=15.0):
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = ec.describe_cache_clusters(CacheClusterId=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "CacheClusterNotFound":
                return True
            raise
        clusters = resp.get("CacheClusters", [])
        if not clusters:
            return True
        if clusters[0]["CacheClusterStatus"] == "deleted":
            return True
        time.sleep(interval_s)
    return False


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
