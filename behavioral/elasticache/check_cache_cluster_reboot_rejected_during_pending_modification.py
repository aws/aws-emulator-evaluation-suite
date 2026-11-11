"""cache-cluster-reboot-rejected-during-pending-modification."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cache-cluster-reboot-rejected-during-pending-modification"
GROUP = "state-machine"
SERVICES = ["elasticache"]

_VPC_CIDR = "10.232.0.0/16"
_SUBNET_CIDR = "10.232.1.0/24"


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RebootCacheCluster is rejected with InvalidCacheClusterState while a
    ModifyCacheCluster change is still being applied, and succeeds once the cluster
    returns to 'available' (positive control)."""
    ec = ctx.client("elasticache")
    subnet_group = _make_cache_subnet_group(ctx, "sim2real-rbt-")
    cluster_id = ctx.unique_name("sim2real-rbt-")

    # A memcached node-count scale-out finishes 'modifying' in minutes; a redis node-type
    # resize replaces the node and can take 20-40 minutes.
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="memcached",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait_gone(ec, cluster_id))
    _wait_for_cc_status(ec, cluster_id, {"available"}, timeout_s=600)

    modify_resp = ec.modify_cache_cluster(
        CacheClusterId=cluster_id,
        NumCacheNodes=2,
        ApplyImmediately=True,
    )
    modify_status = modify_resp["CacheCluster"]["CacheClusterStatus"]
    assert modify_status in ("modifying", "available"), (
        f"expected ModifyCacheCluster to report 'modifying' or 'available', got {modify_status!r}"
    )

    # Right after ApplyImmediately the cluster can still read 'available', and a reboot then
    # is accepted; only once it is 'modifying' is a reboot refused, so wait for that.
    _wait_for_cc_status(ec, cluster_id, {"modifying"}, timeout_s=180, interval_s=3)

    code, message = _error(
        lambda: ec.reboot_cache_cluster(CacheClusterId=cluster_id, CacheNodeIdsToReboot=["0001"])
    )
    # The wire code is "InvalidCacheClusterState", not the model's "...Fault" shape name.
    assert code == "InvalidCacheClusterState", code
    expected = (
        "Can only reboot cache clusters with state in: available, incompatible-parameters, "
        f"snapshotting. Cluster {cluster_id} has state: modifying."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # An accepted reboot would show "rebooting cluster nodes"; a rejected one leaves "modifying".
    after_reject = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0]
    assert after_reject["CacheClusterStatus"] == "modifying", (
        f"expected the rejected reboot to leave status 'modifying', "
        f"got {after_reject['CacheClusterStatus']!r}"
    )

    # A 1 -> 2 node scale-out often takes well over 300 s to return to 'available'.
    _wait_for_cc_status(ec, cluster_id, {"available"}, timeout_s=700)
    described = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"][0]
    assert described["NumCacheNodes"] == 2, described["NumCacheNodes"]

    # Positive control. The status can read 'available' seconds before the scale-out settles,
    # so a reboot may still be briefly refused with InvalidCacheClusterState; poll, bounded.
    reboot_resp = _reboot_with_retry(ec, cluster_id, timeout_s=180, interval_s=5)
    reboot_id = reboot_resp["CacheCluster"]["CacheClusterId"]
    assert reboot_id == cluster_id, (
        f"expected RebootCacheCluster to echo back {cluster_id!r}, got {reboot_id!r}"
    )
    _wait_for_cc_status(ec, cluster_id, {"available"}, timeout_s=300)



def _error(fn):
    """Call fn(); return the botocore Error (Code, Message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_for_cc_status(ec, cluster_id, targets, timeout_s=1200.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        clusters = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"]
        if clusters:
            last = clusters[0]["CacheClusterStatus"]
            if last in targets:
                return clusters[0]
        time.sleep(interval_s)
    raise AssertionError(f"cache cluster {cluster_id} never reached {targets}, last status={last}")


def _reboot_with_retry(ec, cluster_id, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while True:
        try:
            return ec.reboot_cache_cluster(
                CacheClusterId=cluster_id, CacheNodeIdsToReboot=["0001"]
            )
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code != "InvalidCacheClusterState" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
