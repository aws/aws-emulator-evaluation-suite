"""delete-primary-cluster-automatic-failover-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-primary-cluster-automatic-failover-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticache"]


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). A SUCCESS raises AssertionError,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCacheCluster on the primary member of a replication group with automatic failover
    enabled is refused with InvalidCacheClusterState naming the primary and the group, leaving
    every member intact and the group available; the same call on a non-primary member succeeds."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-delpri-")
    subnet_group = _network_cache_subnet_group(ctx, ec)

    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="delete-primary-cluster-automatic-failover rejection test",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=3,  # 1 primary + 2 replicas
        AutomaticFailoverEnabled=True,
        CacheSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_rg_and_wait_gone(ec, rg_id))

    rg = _wait_rg_status(ec, rg_id, "available", timeout_s=1800)
    members = rg["NodeGroups"][0]["NodeGroupMembers"]
    assert len(members) == 3, f"expected 3 members after create, got {len(members)}: {members!r}"
    primary_id = _primary_cluster_id(members)
    assert primary_id is not None, f"no primary member found among {members!r}"
    replica_ids = sorted(m["CacheClusterId"] for m in members if m["CacheClusterId"] != primary_id)
    assert len(replica_ids) == 2, f"expected 2 non-primary members, got {replica_ids!r}"

    code, message = _error(lambda: ec.delete_cache_cluster(CacheClusterId=primary_id))
    assert code == "InvalidCacheClusterState", (
        f"deleting the primary cluster {primary_id!r} of a replication group with automatic "
        f"failover enabled failed with {code!r}, expected 'InvalidCacheClusterState'"
    )
    assert message == (
        f"Cache cluster {primary_id} is serving as primary for replication group {rg_id} "
        "and cannot be deleted. To delete the entire replication group, use DeleteReplicationGroup."
    ), f"unexpected InvalidCacheClusterState message: {message!r}"

    # Effect absent: the group and its membership are unchanged.
    unchanged = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]
    assert unchanged["Status"] == "available", (
        f"group left status {unchanged['Status']!r} after a rejected delete, expected 'available'"
    )
    unchanged_members = unchanged["NodeGroups"][0]["NodeGroupMembers"]
    assert sorted(m["CacheClusterId"] for m in unchanged_members) == sorted(
        m["CacheClusterId"] for m in members
    ), f"membership changed after a rejected delete: {unchanged_members!r}"
    assert _primary_cluster_id(unchanged_members) == primary_id, (
        f"primary changed after a rejected delete: {unchanged_members!r}"
    )

    # Positive control: the identical call on a non-primary member of the same group succeeds,
    # proving the refusal is specific to the primary role rather than DeleteCacheCluster at large.
    ec.delete_cache_cluster(CacheClusterId=replica_ids[0])
    final = _wait_for_member_count(ec, rg_id, 2, timeout_s=1800)
    final_members = sorted(m["CacheClusterId"] for m in final["NodeGroups"][0]["NodeGroupMembers"])
    assert final_members == sorted([primary_id, replica_ids[1]]), (
        f"unexpected membership after deleting a non-primary member: {final_members!r}"
    )


def _primary_cluster_id(members) -> str | None:
    for member in members:
        if member.get("CurrentRole") == "primary":
            return member["CacheClusterId"]
    return None


def _wait_rg_status(ec, rg_id, target_status, timeout_s=1800.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        if groups:
            last = groups[0]
            if last["Status"] == target_status:
                return last
        time.sleep(interval_s)
    raise AssertionError(
        f"replication group {rg_id} never reached status {target_status!r} within {timeout_s}s; last={last!r}"
    )


def _wait_for_member_count(ec, rg_id, expected, timeout_s=1800.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        if groups:
            rg = groups[0]
            last = rg
            members = rg["NodeGroups"][0]["NodeGroupMembers"]
            if rg["Status"] == "available" and len(members) == expected:
                return rg
        time.sleep(interval_s)
    raise AssertionError(
        f"replication group {rg_id} never converged to {expected} node group members "
        f"while available; last={last!r}"
    )


def _network_cache_subnet_group(ctx, client) -> str:
    """An ElastiCache subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-csg-")
    client.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cache_subnet_group(CacheSubnetGroupName=name),
            # DeleteCacheSubnetGroup refuses a group a cluster still holds with CacheSubnetGroupInUse.
            ("CacheSubnetGroupInUse", "InvalidCacheSubnetGroupState"),
            ("CacheSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=250.0, interval_s=2.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _delete_rg_and_wait_gone(ec, rg_id, timeout_s=1500.0, interval_s=2.0):
    """Delete the replication group once it is deletable (retrying while a just-settled group
    transiently refuses, tolerating one already deleting or gone) and wait until it is gone, so
    the subnet group registered before it can be deleted after it."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
                return
            raise
        if not groups:
            return
        if groups[0]["Status"] == "available":
            try:
                ec.delete_replication_group(ReplicationGroupId=rg_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ReplicationGroupNotFoundFault", "InvalidReplicationGroupState"
                ):
                    raise
        time.sleep(interval_s)
    raise AssertionError(f"replication group {rg_id} still present at the teardown deadline")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
