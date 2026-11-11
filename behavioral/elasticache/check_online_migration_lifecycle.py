"""online-migration-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "online-migration-lifecycle"
GROUP = "state-machine"
SERVICES = ["elasticache"]

_NOT_MIGRATING_MESSAGE = (
    "The replication group must be in migrating state to complete the migration. Please retry later."
)
_START_NOT_ALLOWED_MESSAGE = "Replication group must be in available or migrating status to start migration."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartMigration to an unreachable source puts the group in 'modifying', a duplicate is
    rejected with InvalidReplicationGroupState, and the group settles at 'available' (as after
    TestMigration); CompleteMigration, even with Force, is rejected before and after."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-mig-")[:40]

    _budget_start = time.monotonic()
    _CHECK_BUDGET_S = 850.0  # margin below the 900 s per-check timeout

    def _remaining_budget(reserve_s: float = 0.0) -> float:
        left = _CHECK_BUDGET_S - (time.monotonic() - _budget_start) - reserve_s
        return max(20.0, left)

    # Online migration requires automatic failover to be enabled on the target replication
    # group (AWS rejects TestMigration/StartMigration with InvalidParameterValue otherwise),
    # which in turn requires at least one replica node.
    subnet_group = _network_cache_subnet_group(ctx, ec)
    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real online migration target",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=2,
        AutomaticFailoverEnabled=True,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:check", "Value": CHECK},
        ],
        CacheSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_rg_tolerant(ec, rg_id))
    # A 2-node cache.t3.micro replication group with automatic failover needs several hundred
    # seconds to leave 'creating'; a floor is reserved for every later phase.
    _wait_for_rg_status(
        ec, rg_id, "available", timeout_s=_remaining_budget(reserve_s=240.0), interval_s=15
    )

    endpoint_list = [{"Address": "10.0.0.5", "Port": 6379}]

    # Precondition: CompleteMigration is rejected before any migration has ever started.
    code, message = _rejected_with(
        lambda: ec.complete_migration(ReplicationGroupId=rg_id),
        "CompleteMigration with no migration ever started",
    )
    assert code == "InvalidParameterValue", code
    assert message == _NOT_MIGRATING_MESSAGE, message
    status = _describe_rg_status(ec, rg_id)
    assert status == "available", f"expected 'available' after the rejected CompleteMigration, got {status!r}"

    # TestMigration only probes connectivity; it is itself async (the immediate response can
    # report the dedicated transient status 'testing-migration' while the probe runs in the
    # background), and the group settles back at 'available'.
    test_resp = ec.test_migration(ReplicationGroupId=rg_id, CustomerNodeEndpointList=endpoint_list)
    immediate_status = test_resp["ReplicationGroup"]["Status"]
    assert immediate_status in ("available", "modifying", "testing-migration"), (
        f"TestMigration with no migration in flight returned unexpected status {immediate_status!r}"
    )
    status = _wait_for_rg_status(ec, rg_id, "available", timeout_s=180, interval_s=10)
    assert status == "available", f"expected 'available' after the TestMigration probe, got {status!r}"

    # The check holds the in-progress window itself: the duplicate is sent immediately after its
    # own accepted StartMigration, while the group is still 'modifying'.
    ec.start_migration(ReplicationGroupId=rg_id, CustomerNodeEndpointList=endpoint_list)
    code, message = _rejected_with(
        lambda: ec.start_migration(ReplicationGroupId=rg_id, CustomerNodeEndpointList=endpoint_list),
        "a duplicate StartMigration while the first one applies",
    )
    assert code == "InvalidReplicationGroupState", code
    assert message == _START_NOT_ALLOWED_MESSAGE, message

    # The unreachable source never lets the migration reach 'migrating'; the group settles back
    # at its terminal 'available'.
    status = _wait_for_rg_status(
        ec, rg_id, "available", timeout_s=_remaining_budget(reserve_s=30.0), interval_s=10
    )
    assert status == "available", f"expected 'available' after the abandoned migration, got {status!r}"

    # Force stops an in-flight migration; it does not complete one that is no longer in flight.
    code, message = _rejected_with(
        lambda: ec.complete_migration(ReplicationGroupId=rg_id, Force=True),
        "CompleteMigration(Force=True) after the migration was abandoned",
    )
    assert code == "InvalidParameterValue", code
    assert message == _NOT_MIGRATING_MESSAGE, message
    status = _describe_rg_status(ec, rg_id)
    assert status == "available", f"expected 'available' after the rejected CompleteMigration, got {status!r}"


def _rejected_with(fn, description: str):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises immediately, naming the description and the returned response."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to be rejected, but it SUCCEEDED: {result!r}")


def _delete_rg_tolerant(client, rg_id: str) -> None:
    # A group still creating or applying a migration rejects delete with
    # InvalidReplicationGroupState, so that code is retried within a bounded window.
    deadline = time.monotonic() + 1200.0
    while True:
        try:
            client.delete_replication_group(ReplicationGroupId=rg_id)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ReplicationGroupNotFoundFault":
                return
            if code == "InvalidReplicationGroupState" and time.monotonic() < deadline:
                time.sleep(15)
                continue
            raise
    _wait_for_rg_gone(client, rg_id, timeout_s=1200, interval_s=20)


def _describe_rg_status(client, rg_id: str) -> str:
    resp = client.describe_replication_groups(ReplicationGroupId=rg_id)
    groups = resp.get("ReplicationGroups", [])
    if not groups:
        raise AssertionError(f"replication group {rg_id} not found")
    return groups[0]["Status"]


def _wait_for_rg_status(client, rg_id, target, timeout_s=1800.0, interval_s=30.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe_rg_status(client, rg_id)
        if last == target:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"replication group {rg_id} never reached {target!r}, last saw {last!r}")


def _wait_for_rg_gone(client, rg_id, timeout_s=1200.0, interval_s=20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = client.describe_replication_groups(ReplicationGroupId=rg_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
                return
            raise
        if not resp.get("ReplicationGroups"):
            return
        time.sleep(interval_s)
    raise AssertionError(f"replication group {rg_id} was not deleted within {timeout_s}s")


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
