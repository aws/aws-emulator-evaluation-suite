"""cache-subnet-group-dependent-resource-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cache-subnet-group-dependent-resource-lifecycle"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cache subnet group referenced by both a standalone cache cluster and a
    replication group cannot be deleted (CacheSubnetGroupInUse) until every
    dependent is torn down; it then deletes cleanly and transitions to 404."""
    ec = ctx.client("elasticache")
    subnet_ids = _default_vpc_subnet_ids(ctx, count=2)

    subnet_group_name = ctx.unique_name("sim2real-behav-csng-")
    created = ec.create_cache_subnet_group(
        CacheSubnetGroupName=subnet_group_name,
        CacheSubnetGroupDescription="sim2real subnet group dependency check",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["CacheSubnetGroup"]
    ctx.on_cleanup(lambda: _safe_delete_subnet_group(ec, subnet_group_name))
    assert created["CacheSubnetGroupName"] == subnet_group_name, (
        f"expected echoed CacheSubnetGroupName {subnet_group_name!r}, got {created['CacheSubnetGroupName']!r}"
    )
    assert {s["SubnetIdentifier"] for s in created["Subnets"]} == set(subnet_ids), (
        f"expected subnet ids {set(subnet_ids)!r}, got "
        f"{ {s['SubnetIdentifier'] for s in created['Subnets']}!r}"
    )

    described = ec.describe_cache_subnet_groups(CacheSubnetGroupName=subnet_group_name)[
        "CacheSubnetGroups"
    ]
    assert len(described) == 1, f"expected exactly 1 matching subnet group, got {len(described)}"
    assert described[0]["CacheSubnetGroupName"] == subnet_group_name, (
        f"expected {subnet_group_name!r}, got {described[0]['CacheSubnetGroupName']!r}"
    )

    # The standalone cluster and the replication group have independent,
    # unrelated provisioning lifecycles -- kick both creations off back to
    # back (neither call blocks) so their real-AWS provisioning windows
    # overlap in wall-clock time instead of stacking sequentially. The
    # standalone cluster uses Memcached (rather than Redis) purely as a
    # second, unrelated dependent: Memcached clusters provision and tear
    # down markedly faster than Redis replication groups on real AWS.
    cluster_id = ctx.unique_name("sim2real-behav-clu-")
    ec.create_cache_cluster(
        CacheClusterId=cluster_id,
        Engine="memcached",
        CacheNodeType="cache.t3.micro",
        NumCacheNodes=1,
        CacheSubnetGroupName=subnet_group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_cluster(ec, cluster_id))

    rg_id = ctx.unique_name("sim2real-behav-rg-")
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real subnet group dependency check",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        AutomaticFailoverEnabled=False,
        CacheSubnetGroupName=subnet_group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_rg(ec, rg_id))

    # A subnet group referenced by any dependent -- even one still in the
    # middle of provisioning -- cannot be deleted, so the block can be
    # observed immediately without waiting for either dependent to finish
    # creating first.
    code, message = _error(lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=subnet_group_name))
    assert code == "CacheSubnetGroupInUse", f"expected CacheSubnetGroupInUse, got {code!r}"
    in_use_message = f"Cache subnet group {subnet_group_name} is currently in use by a cache cluster."
    assert message == in_use_message, f"expected message {in_use_message!r}, got {message!r}"
    assert ec.describe_cache_subnet_groups(CacheSubnetGroupName=subnet_group_name)["CacheSubnetGroups"], (
        f"expected {subnet_group_name!r} to still be described after the blocked delete"
    )

    # Wait for BOTH dependents to finish provisioning via a single poll loop
    # that checks both statuses every iteration, rather than waiting on the
    # cluster alone and only then looking at the replication group. Deleting
    # the standalone cluster while the replication group is STILL creating on
    # the very same subnet group triggers real cross-resource contention on
    # real AWS (the cluster's ENI teardown queues up behind the replication
    # group's own in-flight ENI provisioning) that has been observed to
    # inflate a normally-fast Memcached cluster deletion to well past 10
    # minutes -- comfortably enough on its own to blow the check's overall
    # time budget. Waiting for the replication group to also finish creating
    # before touching either delete call removes THAT contention window.
    cluster_status, rg_status = _wait_both_available(
        ec, cluster_id, rg_id, timeout_s=780
    )
    assert cluster_status == "available", f"expected cluster {cluster_id} 'available', got {cluster_status!r}"
    assert rg_status == "available", f"expected replication group {rg_id} 'available', got {rg_status!r}"

    # Tear the standalone cluster down first and confirm it is fully gone. Its
    # deletion can exceed 600 s while the replication group shares the subnet
    # group, so the bound below leaves headroom over that.
    ec.delete_cache_cluster(CacheClusterId=cluster_id)
    _wait_cluster_gone(ec, cluster_id, timeout_s=1500)

    # The replication group dependent is still fully present (now
    # 'available', confirmed above) -- the subnet group must still be
    # blocked. This is the substantive "not until every dependent is torn
    # down" claim, not just "not until zero dependents ever existed".
    code_partial, message_partial = _error(
        lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=subnet_group_name)
    )
    assert code_partial == "CacheSubnetGroupInUse", (
        f"expected the subnet group to still be blocked while the "
        f"replication group dependent was still present, got {code_partial!r}"
    )
    assert message_partial == in_use_message, (
        f"expected message {in_use_message!r}, got {message_partial!r}"
    )
    assert ec.describe_cache_subnet_groups(CacheSubnetGroupName=subnet_group_name)["CacheSubnetGroups"], (
        f"expected {subnet_group_name!r} to still be described while the replication group dependent remained"
    )

    ec.delete_replication_group(ReplicationGroupId=rg_id)
    _wait_rg_gone(ec, rg_id, timeout_s=500)

    # No dependents left: deletion now succeeds.
    ec.delete_cache_subnet_group(CacheSubnetGroupName=subnet_group_name)
    code3, message3 = _error(lambda: ec.describe_cache_subnet_groups(CacheSubnetGroupName=subnet_group_name))
    assert code3 == "CacheSubnetGroupNotFoundFault", f"expected CacheSubnetGroupNotFoundFault, got {code3!r}"
    expected3 = f"Cache subnet group {subnet_group_name} not found."
    assert message3 == expected3, f"expected message {expected3!r}, got {message3!r}"


# ===== helpers =====

def _default_vpc_subnet_ids(ctx, count: int) -> list:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to host the cache subnet group")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    ids = list(by_az.values())
    if len(ids) < count:
        raise AssertionError(f"shared network has fewer than {count} distinct-AZ subnets")
    return ids[:count]


def _cluster_status(ec, cluster_id: str) -> str | None:
    clusters = ec.describe_cache_clusters(CacheClusterId=cluster_id)["CacheClusters"]
    return clusters[0]["CacheClusterStatus"] if clusters else None


def _rg_status(ec, rg_id: str) -> str | None:
    groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
    return groups[0]["Status"] if groups else None


def _wait_both_available(ec, cluster_id: str, rg_id: str, timeout_s: float):
    """Bounded poll of BOTH the standalone cache cluster's and the
    replication group's status in a single loop, returning only once both
    have reached 'available'. Checking both per-iteration (rather than
    waiting on one to completion before even looking at the other) is what
    lets their real-AWS provisioning windows overlap in wall-clock time; it
    also means neither dependent's subsequent DELETE is ever issued while
    the other is still mid-creation, avoiding the cross-resource contention
    on the shared subnet group that a creating-vs-deleting overlap causes."""
    deadline = time.monotonic() + timeout_s
    cluster_status = rg_status = None
    while time.monotonic() < deadline:
        cluster_status = _cluster_status(ec, cluster_id)
        rg_status = _rg_status(ec, rg_id)
        if cluster_status == "available" and rg_status == "available":
            return cluster_status, rg_status
        time.sleep(2)
    raise AssertionError(
        f"cluster {cluster_id} / replication group {rg_id} never both reached "
        f"'available': cluster={cluster_status!r}, rg={rg_status!r}"
    )


def _wait_cluster_gone(ec, cluster_id: str, timeout_s: float) -> None:
    """Bounded poll until the standalone cache cluster is fully gone
    (CacheClusterNotFound), rather than merely 'deleting'."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _gone(lambda: ec.describe_cache_clusters(CacheClusterId=cluster_id), "CacheClusterNotFound"):
            return
        time.sleep(2)
    raise AssertionError(f"cache cluster {cluster_id} never fully disappeared")


def _wait_rg_gone(ec, rg_id: str, timeout_s: float) -> None:
    """Bounded poll until the replication group is fully gone
    (ReplicationGroupNotFoundFault), rather than merely 'deleting'."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _gone(lambda: ec.describe_replication_groups(ReplicationGroupId=rg_id), "ReplicationGroupNotFoundFault"):
            return
        time.sleep(2)
    raise AssertionError(f"replication group {rg_id} never fully disappeared")


def _error(fn):
    """Call fn(); return (code, message) from the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


def _gone(describe, not_found_code: str) -> bool:
    """Poll probe: True once `describe` raises `not_found_code`, False while it still succeeds."""
    from botocore.exceptions import ClientError
    try:
        describe()
    except ClientError as err:
        if err.response["Error"]["Code"] == not_found_code:
            return True
        raise
    return False


def _teardown_tolerated(err) -> bool:
    """A teardown delete may find its target already gone or already deleting."""
    code = err.response.get("Error", {}).get("Code") or ""
    return "NotFound" in code or (code.startswith("Invalid") and "State" in code)


def _safe_delete_rg(ec, rg_id: str) -> None:
    from botocore.exceptions import ClientError
    try:
        ec.delete_replication_group(ReplicationGroupId=rg_id)
    except ClientError as err:
        if not _teardown_tolerated(err):
            raise
    _wait_rg_gone(ec, rg_id, timeout_s=900)


def _safe_delete_cluster(ec, cluster_id: str) -> None:
    from botocore.exceptions import ClientError
    try:
        ec.delete_cache_cluster(CacheClusterId=cluster_id)
    except ClientError as err:
        if not _teardown_tolerated(err):
            raise
    _wait_cluster_gone(ec, cluster_id, timeout_s=1500)


def _safe_delete_subnet_group(ec, name: str) -> None:
    """Delete the subnet group, retrying while a dependent is still releasing it."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + 900
    while True:
        try:
            ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
            return
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code") or ""
            if "NotFound" in code:
                return
            if code != "CacheSubnetGroupInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(15)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
