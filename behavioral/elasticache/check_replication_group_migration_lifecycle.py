"""replication-group-migration-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replication-group-migration-lifecycle"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CompleteMigration before StartMigration, DeleteReplicationGroup during a migration and a second
    StartMigration are each refused with their exact code and message while the group survives; a forced
    CompleteMigration echoes the group or is refused, and the blocked delete then succeeds."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-mig-")
    teardown = {}

    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="migration lifecycle check",
        Engine="redis",
        CacheSubnetGroupName=_cache_subnet_group(ctx, ec, teardown),
        # Real ElastiCache rejects StartMigration ("Migration is not supported for auto
        # failover disabled...") unless the replication group has automatic failover enabled,
        # which itself requires at least one replica (NumCacheClusters=2: primary + 1 replica).
        NumCacheClusters=2,
        CacheNodeType="cache.t3.micro",
        AutomaticFailoverEnabled=True,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_replication_group(ec, rg_id, teardown))

    # One wall-clock budget for the whole check, below the suite's ceiling: each phase gets what is
    # left of it, so the phases can never sum past it however the real time splits.
    _budget_start = time.monotonic()
    _CHECK_BUDGET_S = 3400.0

    def _remaining_budget(reserve_s: float = 0.0) -> float:
        left = _CHECK_BUDGET_S - (time.monotonic() - _budget_start) - reserve_s
        return max(30.0, left)

    # The 2-node create can take well over 5 minutes; a reserve of the budget is kept for the forced
    # completion, the tracking clear and the delete.
    _CREATE_WAIT_CAP_S = 1200.0
    _CREATE_WAIT_RESERVE_S = 1400.0  # floor left for force-complete + tracking clear + delete
    _wait_for_rg_status(
        ec,
        rg_id,
        {"available"},
        timeout_s=min(_CREATE_WAIT_CAP_S, _remaining_budget(reserve_s=_CREATE_WAIT_RESERVE_S)),
    )

    # CompleteMigration before any StartMigration must be rejected: no migration is in flight.
    # Real ElastiCache reports this as a parameter validation failure rather than the
    # dedicated ReplicationGroupNotUnderMigrationFault shape.
    code, message = _error(lambda: ec.complete_migration(ReplicationGroupId=rg_id, Force=True))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    expected = "The replication group must be in migrating state to complete the migration. Please retry later."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # StartMigration begins the online migration and moves the group out of 'available'.
    ec.start_migration(
        ReplicationGroupId=rg_id,
        CustomerNodeEndpointList=[{"Address": "203.0.113.10", "Port": 6379}],
    )

    # Delete must be blocked while migration is active -- the group is not 'available'.
    # Real ElastiCache reports this rejection as "InvalidReplicationGroupState" on the
    # wire -- NOT the "...Fault"-suffixed shape name from the API model.
    code, message = _error(lambda: ec.delete_replication_group(ReplicationGroupId=rg_id))
    assert code == "InvalidReplicationGroupState", f"expected InvalidReplicationGroupState, got {code}"
    expected = f"Replication group {rg_id} has status modifying which is not valid for deletion."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    # The forbidden effect (deletion) did not happen: the group still describes successfully.
    still_there = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
    assert len(still_there) == 1 and still_there[0]["ReplicationGroupId"] == rg_id, (
        f"expected exactly one replication group {rg_id} to still exist, got {still_there}"
    )

    # A second StartMigration during the migration is refused with the generic InvalidReplicationGroupState,
    # not the model's ReplicationGroupAlreadyUnderMigrationFault.
    code, message = _error(
        lambda: ec.start_migration(
            ReplicationGroupId=rg_id,
            CustomerNodeEndpointList=[{"Address": "203.0.113.11", "Port": 6379}],
        )
    )
    assert code == "InvalidReplicationGroupState", f"expected InvalidReplicationGroupState, got {code}"
    expected = "Replication group must be in available or migrating status to start migration."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # CompleteMigration(Force=True) stops a migration without syncing; against a source that was
    # never reachable it is refused with the migrating-state error, or echoes the group if the
    # migration registered. The retry covers the brief post-StartMigration registration window.
    resp, err = _try_complete_migration(
        ec, rg_id, budget_s=min(600.0, _remaining_budget(reserve_s=900.0))
    )
    if resp is not None:
        assert resp["ReplicationGroup"]["ReplicationGroupId"] == rg_id, (
            f"expected CompleteMigration to echo {rg_id}, got {resp['ReplicationGroup'].get('ReplicationGroupId')}"
        )
    else:
        err_code = err.response["Error"]["Code"]
        assert err_code == "InvalidParameterValue", (
            f"expected CompleteMigration(Force=True) against a never-reachable source to be "
            f"rejected with InvalidParameterValue, got {err_code!r}"
        )
        expected = "The replication group must be in migrating state to complete the migration. Please retry later."
        assert err.response["Error"].get("Message") == expected, (
            f"expected message {expected!r}, got {err.response['Error'].get('Message')!r}"
        )

    # Positive control for the blocked delete: once ElastiCache clears the migration tracking (on
    # its own timeline), the identical DeleteReplicationGroup succeeds; never clearing fails.
    _delete_once_migration_clears(ec, rg_id, timeout_s=_remaining_budget())


def _error(fn):
    """Call fn(); return (code, message) from the ClientError it must raise. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _try_complete_migration(ec, rg_id, budget_s, interval_s=15.0):
    """Best-effort CompleteMigration(Force=True) for a bounded window, returning
    ``(response, None)`` on success or ``(None, last ClientError)``.

    Force stops a migration without syncing; it does not make a never-reachable source sync, so a
    rejection is a real outcome. The window covers only the post-StartMigration registration race."""
    deadline = time.monotonic() + budget_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ec.complete_migration(ReplicationGroupId=rg_id, Force=True), None
        except ClientError as e:
            last_err = e
            time.sleep(interval_s)
    return None, last_err


def _delete_once_migration_clears(ec, rg_id, timeout_s, interval_s=15.0):
    """DeleteReplicationGroup, retried until ElastiCache has cleared the migration tracking.

    This is the positive control for the delete-blocked assertion: the same call that was
    rejected with InvalidReplicationGroupState while the migration was in flight must
    eventually succeed. Only that one rejection is retried; anything else propagates, and
    running out of the window is a FAIL rather than a swallowed no-op."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            ec.delete_replication_group(ReplicationGroupId=rg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ReplicationGroupNotFoundFault":
                return
            if code not in ("InvalidReplicationGroupState", "InvalidReplicationGroupStateFault"):
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(
        f"DeleteReplicationGroup on {rg_id} never became possible within {timeout_s}s -- the "
        f"migration tracking never cleared; last error: {last_err}"
    )


def _cache_subnet_group(ctx, ec, teardown) -> str:
    """A cache subnet group over the run's network, deleted once the replication group releases it."""
    name = ctx.unique_name("sim2real-mig-sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real migration lifecycle check",
        SubnetIds=ctx.network().subnet_ids,
    )

    def delete():
        # DeleteCacheSubnetGroup answers CacheSubnetGroupInUse until the replication group is deleted.
        deadline = _deadline(teardown)
        while True:
            try:
                ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
                return
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "CacheSubnetGroupNotFoundFault":
                    return
                if code != "CacheSubnetGroupInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(delete)
    return name


# Inside the 1800 s elasticache cleanup budget, one deadline shared by every teardown of a run.
_TEARDOWN_S = 1680.0


def _deadline(shared):
    """The run's teardown deadline, fixed by the first teardown that runs."""
    return shared.setdefault("t", time.monotonic() + _TEARDOWN_S)


def _delete_replication_group(ec, rg_id, shared):
    """Delete the group and wait every 2 s until it is gone. DeleteReplicationGroup answers
    InvalidReplicationGroupState while the group is creating, modifying or migrating, which is retried;
    a group already deleting is awaited. Any other failure, or the deadline passing, raises."""
    deadline = _deadline(shared)
    while True:
        try:
            groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
            if not groups:
                return
            if groups[0]["Status"] != "deleting":
                ec.delete_replication_group(ReplicationGroupId=rg_id)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ReplicationGroupNotFoundFault":
                return
            if code != "InvalidReplicationGroupState":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"replication group {rg_id} still present at the teardown deadline")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
