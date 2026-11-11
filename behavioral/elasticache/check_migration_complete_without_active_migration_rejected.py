"""migration-complete-without-active-migration-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "migration-complete-without-active-migration-rejected"
GROUP = "state-machine"
SERVICES = ["elasticache"]

_NOT_MIGRATING = (
    "The replication group must be in migrating state to complete the migration. Please retry later."
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CompleteMigration on a group never migrated is refused with InvalidParameterValue and the
    migrating-state message; a duplicate StartMigration is refused with InvalidReplicationGroupState and its
    exact message; a forced CompleteMigration echoes the group or gives the migrating-state refusal."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-behav-nomig-")
    subnet_group = _cache_subnet_group(ctx, ec)

    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real complete-migration-without-migration rejection check",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        # Migration APIs require automatic failover, which needs a replica; otherwise StartMigration
        # fails with an unrelated InvalidParameterValueException.
        NumCacheClusters=2,
        AutomaticFailoverEnabled=True,
        CacheSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_rg(ec, rg_id))
    assert _wait_rg_status(ec, rg_id, {"available"}, timeout_s=900) == "available"

    # Never under migration: CompleteMigration is refused with InvalidParameterValue. Throttling and
    # 5xx codes are retried a bounded number of times because the group has just finished its create.
    from botocore.exceptions import ClientError
    TRANSIENT_CODES = {
        "ThrottlingException",
        "Throttling",
        "RequestLimitExceeded",
        "TooManyRequestsException",
        "ServiceUnavailable",
        "ServiceUnavailableException",
        "InternalFailure",
        "InternalServerError",
    }
    no_migration_result = None
    code = message = None
    for attempt in range(6):
        try:
            no_migration_result = ec.complete_migration(ReplicationGroupId=rg_id)
            break
        except ClientError as err:
            code, message = err.response["Error"]["Code"], err.response["Error"].get("Message")
            if code in TRANSIENT_CODES and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            break
    assert no_migration_result is None, (
        f"CompleteMigration on a never-migrated replication group SUCCEEDED: {no_migration_result!r}"
    )
    assert code == "InvalidParameterValue", (
        f"unexpected rejection code for CompleteMigration without an active migration: {code!r}"
    )
    assert message == _NOT_MIGRATING, f"expected {_NOT_MIGRATING!r}, got {message!r}"
    # The forbidden effect (a lasting status change) did not happen.
    assert _wait_rg_status(ec, rg_id, {"available"}, timeout_s=10) == "available"

    # Positive control: the migration workflow is live. There is no 'migrating' Status (the group
    # stays 'available'), so a rejected duplicate StartMigration is the evidence of a migration.
    ec.start_migration(
        ReplicationGroupId=rg_id,
        CustomerNodeEndpointList=[{"Address": "203.0.113.20", "Port": 6379}],
    )
    # Issued immediately: the TEST-NET-3 source is unreachable and AWS can abandon the migration
    # within minutes, closing the window in which the duplicate is rejected. While the group is
    # still 'modifying' the rejection is InvalidReplicationGroupState.
    second_code, second_message = _error_code(
        lambda: ec.start_migration(
            ReplicationGroupId=rg_id,
            CustomerNodeEndpointList=[{"Address": "203.0.113.20", "Port": 6379}],
        )
    )
    assert second_code == "InvalidReplicationGroupState", (
        f"unexpected rejection code for a duplicate StartMigration: {second_code!r}"
    )
    expected = "Replication group must be in available or migrating status to start migration."
    assert second_message == expected, f"expected {expected!r}, got {second_message!r}"

    assert _wait_rg_status(ec, rg_id, {"available"}, timeout_s=300) == "available"

    # Force stops a migration rather than syncing an unreachable source, so either outcome is
    # accepted, each held to its own assertion.
    forced, forced_err = _try_complete_migration(ec, rg_id, budget_s=600.0)
    if forced is not None:
        assert forced["ReplicationGroup"]["ReplicationGroupId"] == rg_id, (
            f"expected CompleteMigration to echo {rg_id}, got {forced['ReplicationGroup']!r}"
        )
    else:
        forced_code = forced_err.response["Error"]["Code"]
        forced_message = forced_err.response["Error"].get("Message")
        assert forced_code == "InvalidParameterValue", (
            f"expected CompleteMigration(Force=True) against a never-reachable source to be "
            f"rejected with InvalidParameterValue, got {forced_code!r}"
        )
        assert forced_message == _NOT_MIGRATING, f"expected {_NOT_MIGRATING!r}, got {forced_message!r}"
    assert _wait_rg_status(ec, rg_id, {"available"}, timeout_s=300) == "available"


def _try_complete_migration(ec, rg_id: str, budget_s: float, interval_s: float = 15.0):
    """Best-effort CompleteMigration(Force=True) for a bounded window covering the brief
    post-StartMigration registration race; returns ``(resp, None)`` or ``(None, ClientError)``."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + budget_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ec.complete_migration(ReplicationGroupId=rg_id, Force=True), None
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    return None, last_err


def _wait_rg_status(ec, rg_id: str, targets: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        status = groups[0]["Status"]
        if status in targets:
            return status
        time.sleep(5)
    raise AssertionError(f"replication group {rg_id} never reached {targets}, last status={status}")


def _error_code(fn):
    """Call fn(); return the (code, message) of the ClientError it must raise. An unexpected SUCCESS
    raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _cache_subnet_group(ctx, ec) -> str:
    """A cache subnet group over the run's network, deleted once the replication group releases it."""
    name = ctx.unique_name("sim2real-behav-nomig-sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real complete-migration check",
        SubnetIds=ctx.network().subnet_ids,
    )

    def delete():
        from botocore.exceptions import ClientError
        # DeleteCacheSubnetGroup answers CacheSubnetGroupInUse until the replication group is deleted.
        deadline = time.monotonic() + 1500
        while True:
            try:
                ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
                return
            except ClientError as err:
                code = err.response["Error"]["Code"]
                if code == "CacheSubnetGroupNotFoundFault":
                    return
                if code != "CacheSubnetGroupInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(delete)
    return name


# Inside the 1800 s elasticache cleanup budget; the subnet group delete after it returns as soon
# as the group is gone.
_RG_TEARDOWN_S = 1500.0


def _safe_delete_rg(ec, rg_id: str) -> None:
    """Delete the group and wait every 2 s until it is gone. DeleteReplicationGroup answers
    InvalidReplicationGroupState while the group is modifying or migrating, which is retried; a
    group already deleting is awaited. Any other failure, or the deadline passing, raises."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + _RG_TEARDOWN_S
    status = None
    while True:
        try:
            groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
            if not groups:
                return
            status = groups[0]["Status"]
            if status != "deleting":
                ec.delete_replication_group(ReplicationGroupId=rg_id)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ReplicationGroupNotFoundFault":
                return
            if code != "InvalidReplicationGroupState":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"replication group {rg_id} still {status!r} at the teardown deadline")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
