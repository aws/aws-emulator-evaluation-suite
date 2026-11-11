"""test-failover-state-gating."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-failover-state-gating"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """TestFailover on an unknown node group fails with NodeGroupNotFoundFault and its exact message; a
    second TestFailover right after an accepted one fails with TestFailoverNotAvailableFault ("Test
    failover already in progress") and leaves the member roles unchanged."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-failover-")

    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="test failover gating check",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=2,
        AutomaticFailoverEnabled=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _best_effort_delete(ec, rg_id))
    rg = _wait_for_rg_status(ec, rg_id, {"available"}, timeout_s=1500)
    node_group_id = rg["NodeGroups"][0]["NodeGroupId"]
    members = len(rg["NodeGroups"][0]["NodeGroupMembers"])
    assert members == 2, f"expected 2 node group members, got {members}"

    # A node group that does not exist on the replication group must be refused.
    code, message = _error(
        lambda: ec.test_failover(ReplicationGroupId=rg_id, NodeGroupId="9999")
    )
    assert code == "NodeGroupNotFoundFault", f"expected NodeGroupNotFoundFault, got {code} ({message!r})"
    assert message == f"Node group 9999 was not found for replication group {rg_id}", (
        f"expected the exact NodeGroupNotFound message, got {message!r}"
    )
    # No effect: the group is still 'available' and untouched.
    still_available = _describe_rg(ec, rg_id)
    assert still_available["Status"] == "available", (
        f"expected 'available' after a rejected TestFailover, got {still_available['Status']!r}"
    )

    # Positive control: the real test-failover on the existing node group is accepted.
    ec.test_failover(ReplicationGroupId=rg_id, NodeGroupId=node_group_id)
    roles_after_first = _roles(_node_group(_describe_rg(ec, rg_id), node_group_id))

    # A second TestFailover call on the same node group right after the first must be
    # refused: ElastiCache enforces an internal per-node-group cooldown here, and models
    # the conflict with its own dedicated fault rather than the generic
    # InvalidReplicationGroupStateFault.
    code, message = _error(
        lambda: ec.test_failover(ReplicationGroupId=rg_id, NodeGroupId=node_group_id)
    )
    assert code == "TestFailoverNotAvailableFault", (
        f"expected TestFailoverNotAvailableFault, got {code} ({message!r})"
    )
    assert message == "Test failover already in progress", (
        f"expected the exact TestFailoverNotAvailable message, got {message!r}"
    )
    # No effect from the rejected call: no further primary/replica role change on top of
    # whatever the first, accepted call already did.
    roles_after_reject = _roles(_node_group(_describe_rg(ec, rg_id), node_group_id))
    assert roles_after_reject == roles_after_first, (
        f"rejected TestFailover changed member roles from {roles_after_first!r} to "
        f"{roles_after_reject!r}"
    )

    # Restore: the cooldown is not visible as a Status transition on either the replication
    # group or the node group (both stay 'available' throughout), so wait it out by retrying
    # the actual call, bounded, until it stops being refused.
    _retry_failover_until_accepted(ec, rg_id, node_group_id, timeout_s=1500, interval_s=20)

    # Independent terminal read: the group settles back to 'available' on the same node group.
    rg = _wait_for_rg_status(ec, rg_id, {"available"}, timeout_s=1500)
    assert rg["NodeGroups"][0]["NodeGroupId"] == node_group_id, (
        f"expected node group {node_group_id!r} after the retried failover, "
        f"got {rg['NodeGroups'][0]['NodeGroupId']!r}"
    )


def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError but the call SUCCEEDED")


def _describe_rg(ec, rg_id):
    return ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]


def _node_group(rg, node_group_id):
    return next(g for g in rg["NodeGroups"] if g["NodeGroupId"] == node_group_id)


def _roles(node_group):
    return sorted(
        (m["CacheClusterId"], m.get("CurrentRole")) for m in node_group["NodeGroupMembers"]
    )


def _wait_for_rg_status(ec, rg_id, targets, timeout_s=1500.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        if groups:
            last = groups[0]["Status"]
            if last in targets:
                return groups[0]
        time.sleep(interval_s)
    raise AssertionError(f"replication group {rg_id} never reached {targets}, last status={last}")


def _retry_failover_until_accepted(ec, rg_id, node_group_id, timeout_s=1500.0, interval_s=15.0):
    """Retry TestFailover while the cooldown refuses it; any other error fails the check."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ec.test_failover(ReplicationGroupId=rg_id, NodeGroupId=node_group_id)
            return
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "TestFailoverNotAvailableFault":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"TestFailover on {node_group_id} was still refused after {timeout_s}s")


def _best_effort_delete(ec, rg_id):
    try:
        ec.delete_replication_group(ReplicationGroupId=rg_id)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ReplicationGroupNotFoundFault",)
            or (exc.response["Error"]["Code"] == "InvalidReplicationGroupState" and "has status deleting" in exc.response["Error"].get("Message", ""))
        ):
            raise


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
