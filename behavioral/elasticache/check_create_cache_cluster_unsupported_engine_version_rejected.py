"""create-cache-cluster-unsupported-engine-version-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-cache-cluster-unsupported-engine-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticache"]

_VPC_CIDR = "10.227.0.0/16"
_SUBNET_CIDR = "10.227.1.0/24"


@tags("axis:rejection", "cap:c1", "cap:c4", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Requesting an EngineVersion that is absent from DescribeCacheEngineVersions is
    rejected synchronously at CreateCacheCluster time, not accepted and left to fail
    asynchronously during provisioning."""
    ec = ctx.client("elasticache")
    subnet_group = _make_cache_subnet_group(ctx, "sim2real-eccver-")

    versions = ec.describe_cache_engine_versions(Engine="redis")["CacheEngineVersions"]
    assert versions, "no redis engine versions returned by DescribeCacheEngineVersions"
    known_versions = {v["EngineVersion"] for v in versions}
    bogus_version = "99.99.99"
    assert bogus_version not in known_versions, (
        f"{bogus_version!r} is a real redis EngineVersion per DescribeCacheEngineVersions; "
        "pick a different bogus value"
    )

    bad_id = ctx.unique_name("sim2real-eccbad-")
    ctx.on_cleanup(lambda: _delete_cluster_when_available(ec, bad_id))
    code, message = _error(
        lambda: ec.create_cache_cluster(
            CacheClusterId=bad_id,
            Engine="redis",
            EngineVersion=bogus_version,
            CacheNodeType="cache.t3.micro",
            NumCacheNodes=1,
            CacheSubnetGroupName=subnet_group,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code}"
    expected = f"Cannot find version {bogus_version} for redis"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no cluster was ever created for the rejected request.
    not_found_code, not_found_message = _error(lambda: ec.describe_cache_clusters(CacheClusterId=bad_id))
    assert not_found_code == "CacheClusterNotFound", f"expected CacheClusterNotFound, got {not_found_code}"
    expected_nf = f"CacheCluster not found: {bad_id}"
    assert not_found_message == expected_nf, f"expected message {expected_nf!r}, got {not_found_message!r}"

    # Positive control: a real, listed EngineVersion is accepted and provisions.
    good_id = ctx.unique_name("sim2real-eccok-")
    good_version = sorted(known_versions)[-1]
    ec.create_cache_cluster(
        CacheClusterId=good_id,
        Engine="redis",
        EngineVersion=good_version,
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_cluster_when_available(ec, good_id))
    cluster = _poll_until(
        lambda: _cache_cluster(ec, good_id),
        lambda c: c is not None and c["CacheClusterStatus"] in ("available", "restore-failed"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert cluster["CacheClusterStatus"] == "available", (
        f"positive-control cluster ended in status={cluster['CacheClusterStatus']!r}"
    )


def _error(fn):
    """Call fn(); return the botocore Error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _cache_cluster(ec, cluster_id):
    try:
        clusters = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "CacheClusterNotFound":
            return None
        raise
    return clusters[0] if clusters else None


def _delete_cluster_when_available(ec, cluster_id):
    if _cache_cluster(ec, cluster_id) is None:
        return
    try:
        _poll_until(
            lambda: _cache_cluster(ec, cluster_id),
            lambda c: c is not None and c["CacheClusterStatus"] == "available",
            timeout_s=900.0,
            interval_s=15.0,
        )
    except AssertionError:
        pass
    try:
        ec.delete_cache_cluster(CacheClusterId=cluster_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "CacheClusterNotFound":
            raise
    _poll_until(
        lambda: _cache_cluster(ec, cluster_id),
        lambda c: c is None,
        timeout_s=900.0,
        interval_s=15.0,
    )


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
