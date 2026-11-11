"""create-cache-cluster-missing-required-parameter-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cache-cluster-missing-required-parameter-rejected"
GROUP = "error-semantics"
SERVICES = ["elasticache"]

_VPC_CIDR = "10.226.0.0/16"
_SUBNET_CIDR = "10.226.1.0/24"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCacheCluster for a standalone cluster (no ReplicationGroupId) omitting
    the conditionally-required CacheNodeType is rejected with InvalidParameterValue
    rather than being accepted with some silently-chosen default node type."""
    ec = ctx.client("elasticache")
    subnet_group = _make_cache_subnet_group(ctx, "sim2real-eccmiss-")
    bad_id = ctx.unique_name("sim2real-eccmiss-")
    ctx.on_cleanup(lambda: _delete_cache_cluster(ctx, bad_id))

    def _create_missing_node_type():
        ec.create_cache_cluster(
            CacheClusterId=bad_id,
            Engine="memcached",
            NumCacheNodes=1,
            CacheSubnetGroupName=subnet_group,
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )

    code, message = _error(_create_missing_node_type)
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    expected = "The parameter CacheNodeType must be provided and must not be null."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the cluster was never created
    code2, message2 = _error(lambda: ec.describe_cache_clusters(CacheClusterId=bad_id))
    assert code2 == "CacheClusterNotFound", f"expected CacheClusterNotFound, got {code2}"
    expected2 = f"CacheCluster not found: {bad_id}"
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"

    # positive control: the same request with CacheNodeType supplied succeeds
    good_id = ctx.unique_name("sim2real-eccok-")
    ec.create_cache_cluster(
        CacheClusterId=good_id,
        Engine="memcached",
        NumCacheNodes=1,
        CacheNodeType="cache.t3.micro",
        CacheSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cache_cluster(ctx, good_id))
    status = _wait_for_cache_cluster_status(ctx, good_id, {"available"}, timeout_s=900)
    assert status == "available", f"positive-control cluster never became available: {status}"


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _wait_for_cache_cluster_status(ctx, cluster_id, target_statuses, timeout_s=900.0, interval_s=15.0):
    ec = ctx.client("elasticache")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = ec.describe_cache_clusters(CacheClusterId=cluster_id)
        clusters = resp.get("CacheClusters", [])
        if clusters:
            status = clusters[0]["CacheClusterStatus"]
            if status in target_statuses:
                return status
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} never reached {target_statuses}, last status={status}")


def _delete_cache_cluster(ctx, cluster_id):
    ec = ctx.client("elasticache")
    try:
        _wait_for_cache_cluster_status(ctx, cluster_id, {"available"}, timeout_s=900)
    except AssertionError:
        pass
    except ClientError as e:
        if e.response["Error"]["Code"] == "CacheClusterNotFound":
            return
        raise
    try:
        ec.delete_cache_cluster(CacheClusterId=cluster_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "CacheClusterNotFound":
            raise
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            ec.describe_cache_clusters(CacheClusterId=cluster_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "CacheClusterNotFound":
                return
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
