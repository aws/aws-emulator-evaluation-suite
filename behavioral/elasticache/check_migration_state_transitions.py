"""migration-state-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "migration-state-transitions"
GROUP = "state-machine"
SERVICES = ["elasticache"]

_NOT_MIGRATING_MESSAGE = (
    "The replication group must be in migrating state to complete the migration. Please retry later."
)
_START_NOT_ALLOWED_MESSAGE = "Replication group must be in available or migrating status to start migration."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartMigration keeps the group 'available' and a duplicate StartMigration is refused while
    it applies; TestMigration is usable mid-flight; CompleteMigration, with and without Force, is
    refused with InvalidParameterValue once the unreachable-source migration is abandoned."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-behav-mig-")

    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real migration state-machine check",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        # Migration APIs (Start/Test/CompleteMigration) require automatic
        # failover to be enabled, which in turn requires at least one
        # replica; otherwise StartMigration is rejected outright with
        # InvalidParameterValueException before any migration state
        # transition can be observed.
        NumCacheClusters=2,
        AutomaticFailoverEnabled=True,
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _safe_delete_rg(ec, rg_id))

    assert _wait_rg_status(ec, rg_id, {"available"}, timeout_s=900) == "available"

    endpoint_list = [{"Address": "203.0.113.10", "Port": 6379}]  # TEST-NET-3: unreachable
    started = ec.start_migration(
        ReplicationGroupId=rg_id, CustomerNodeEndpointList=endpoint_list
    )["ReplicationGroup"]
    # There is no distinct 'migrating' Status, but StartMigration transiently flips the group to
    # 'modifying', which can last well past a few seconds; hence a generous bounded poll.
    assert started["Status"] in ("available", "modifying")

    # A rejected second StartMigration is the evidence of the migration. Captured immediately: AWS
    # can abandon an unreachable (TEST-NET-3) source within minutes. While the group is 'modifying'
    # the refusal is InvalidReplicationGroupState.
    code, message = _rejection(
        lambda: ec.start_migration(
            ReplicationGroupId=rg_id, CustomerNodeEndpointList=endpoint_list
        )
    )
    assert (code, message) == ("InvalidReplicationGroupState", _START_NOT_ALLOWED_MESSAGE), (
        f"duplicate StartMigration while the first applies: code {code!r}, message {message!r}"
    )
    assert _wait_rg_status(ec, rg_id, {"available"}, timeout_s=300) == "available"

    # TestMigration is usable mid-flight: it does not error while under migration.
    test_result = ec.test_migration(
        ReplicationGroupId=rg_id, CustomerNodeEndpointList=endpoint_list
    )
    assert "ReplicationGroup" in test_result
    assert _wait_rg_status(ec, rg_id, {"available"}, timeout_s=300) == "available"

    # Force stops an in-flight migration; it does not complete one whose unreachable source
    # was abandoned, so the call is refused.
    code, message = _rejection(lambda: ec.complete_migration(ReplicationGroupId=rg_id, Force=True))
    assert (code, message) == ("InvalidParameterValue", _NOT_MIGRATING_MESSAGE), (
        f"CompleteMigration(Force=True) on the abandoned migration: code {code!r}, message {message!r}"
    )
    final_status = _wait_rg_status(ec, rg_id, {"available"}, timeout_s=300)
    assert final_status == "available"

    # CompleteMigration is refused: the group is no longer under migration.
    code2, message2 = _rejection(lambda: ec.complete_migration(ReplicationGroupId=rg_id))
    assert (code2, message2) == ("InvalidParameterValue", _NOT_MIGRATING_MESSAGE), (
        f"CompleteMigration without an active migration: code {code2!r}, message {message2!r}"
    )
    assert _wait_rg_status(ec, rg_id, {"available"}, timeout_s=10) == "available"


def _wait_rg_status(ec, rg_id: str, target_statuses: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        status = groups[0]["Status"]
        if status in target_statuses:
            return status
        time.sleep(5)
    raise AssertionError(f"replication group {rg_id} never reached {target_statuses}, last status={status}")


def _rejection(fn):
    """Call fn(); return the (code, message) of the ClientError it must raise. An unexpected SUCCESS
    raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe_delete_rg(ec, rg_id: str) -> None:
    from botocore.exceptions import ClientError
    try:
        ec.delete_replication_group(ReplicationGroupId=rg_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
            return
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
