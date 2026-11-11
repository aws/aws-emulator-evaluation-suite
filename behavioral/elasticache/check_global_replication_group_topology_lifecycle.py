"""global-replication-group-topology-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-replication-group-topology-lifecycle"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A primary-only Global datastore settles after a description modify that sticks, refuses
    disassociating its primary with the exact InvalidParameterValue message (primary stays a
    member), and after deletion with the primary retained the primary can itself be deleted."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-grgprim-")
    suffix = ctx.unique_name("sim2realgds").replace("-", "")[:16]

    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="global datastore primary",
        Engine="redis",
        # Global Datastore rejects T-family node types (InvalidParameterValueException);
        # it requires a current-generation non-burstable type such as M5/R5+.
        CacheNodeType="cache.m5.large",
        NumNodeGroups=1,
        # No replica: nothing asserted depends on one, and it adds minutes of provisioning.
        ReplicasPerNodeGroup=0,
        AutomaticFailoverEnabled=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _best_effort_delete_rg(ec, rg_id))
    _wait_for_rg_status(ec, rg_id, {"available"}, timeout_s=900)

    grg = ec.create_global_replication_group(
        GlobalReplicationGroupIdSuffix=suffix,
        PrimaryReplicationGroupId=rg_id,
        GlobalReplicationGroupDescription="topology lifecycle check",
    )["GlobalReplicationGroup"]
    grg_id = grg["GlobalReplicationGroupId"]
    ctx.on_cleanup(lambda: _best_effort_delete_grg(ec, grg_id))
    # A Global datastore with only a primary member settles at "primary-only"; "available"
    # needs an associated secondary region.
    _wait_for_grg_status(ec, grg_id, {"available", "primary-only"}, timeout_s=600)

    ec.modify_global_replication_group(
        GlobalReplicationGroupId=grg_id,
        ApplyImmediately=True,
        GlobalReplicationGroupDescription="topology lifecycle check - updated",
    )
    grg = _wait_for_grg_status(ec, grg_id, {"available", "primary-only"}, timeout_s=600)
    assert grg["GlobalReplicationGroupDescription"] == "topology lifecycle check - updated", (
        f"expected the modified description to stick, got {grg['GlobalReplicationGroupDescription']!r}"
    )

    # Only secondaries can be disassociated. The wire code is InvalidParameterValue, not the
    # model's InvalidGlobalReplicationGroupStateFault.
    code, message = _error(
        lambda: ec.disassociate_global_replication_group(
            GlobalReplicationGroupId=grg_id,
            ReplicationGroupId=rg_id,
            ReplicationGroupRegion=ctx.region,
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == (
        "Cannot disassociate primary replication group. Primary Replication Group will be "
        "disassociated when you delete the Global Replication Group."
    ), f"unexpected refusal message for disassociating the primary: {message!r}"
    grg_after = ec.describe_global_replication_groups(
        GlobalReplicationGroupId=grg_id, ShowMemberInfo=True
    )["GlobalReplicationGroups"][0]
    member_ids = {m["ReplicationGroupId"] for m in grg_after.get("Members", [])}
    assert rg_id in member_ids, f"expected {rg_id} to remain a member, got {member_ids}"

    # The global group's own disappearance (up to ~10 min) is left to cleanup, not awaited.
    ec.delete_global_replication_group(
        GlobalReplicationGroupId=grg_id, RetainPrimaryReplicationGroup=True
    )
    # The primary's GlobalReplicationGroupInfo clears asynchronously; deleting it before then
    # is rejected as still a member of a global replication group.
    _wait_for_rg_grg_disassociated(ec, rg_id, timeout_s=300, interval_s=10)
    ec.delete_replication_group(ReplicationGroupId=rg_id)
    _wait_for_rg_deleted(ec, rg_id, timeout_s=900, interval_s=10)



def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises.
    An unexpected SUCCESS raises rather than reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_rg_status(ec, rg_id, targets, timeout_s=1200.0, interval_s=15.0):
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


def _wait_for_rg_deleted(ec, rg_id, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ec.describe_replication_groups(ReplicationGroupId=rg_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"replication group {rg_id} was never deleted within {timeout_s}s")


def _wait_for_grg_status(ec, grg_id, targets, timeout_s=1500.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        groups = ec.describe_global_replication_groups(
            GlobalReplicationGroupId=grg_id, ShowMemberInfo=True
        )["GlobalReplicationGroups"]
        if groups:
            last = groups[0]["Status"]
            if last in targets:
                return groups[0]
        time.sleep(interval_s)
    raise AssertionError(f"global replication group {grg_id} never reached {targets}, last status={last}")


def _wait_for_rg_grg_disassociated(ec, rg_id, timeout_s=300.0, interval_s=10.0):
    """Poll until the primary's GlobalReplicationGroupInfo (cleared asynchronously by
    DeleteGlobalReplicationGroup) is gone, so DeleteReplicationGroup is not rejected."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        if groups:
            info = groups[0].get("GlobalReplicationGroupInfo") or {}
            last = info.get("GlobalReplicationGroupId")
            if not last:
                return groups[0]
        time.sleep(interval_s)
    raise AssertionError(
        f"replication group {rg_id} still linked to global replication group {last} after {timeout_s}s"
    )


def _wait_for_grg_deleted(ec, grg_id, timeout_s=600.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ec.describe_global_replication_groups(GlobalReplicationGroupId=grg_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "GlobalReplicationGroupNotFoundFault":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"global replication group {grg_id} was never deleted within {timeout_s}s")


def _best_effort_delete_rg(ec, rg_id):
    try:
        ec.delete_replication_group(ReplicationGroupId=rg_id)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ReplicationGroupNotFoundFault",)
            or (exc.response["Error"]["Code"] == "InvalidReplicationGroupState" and "has status deleting" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _best_effort_delete_grg(ec, grg_id):
    try:
        ec.delete_global_replication_group(
            GlobalReplicationGroupId=grg_id, RetainPrimaryReplicationGroup=True
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "GlobalReplicationGroupNotFoundFault":
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
