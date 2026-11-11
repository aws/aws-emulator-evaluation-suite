"""increase-replica-count-exceeds-limit-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "increase-replica-count-exceeds-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Valkey/Redis OSS (cluster mode disabled) replication group supports at most
    5 read replicas (https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/Replication.AddReadReplica.html).
    Requesting 6 is rejected outright, not accepted and silently capped at 5."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-ecrepl-")
    made: dict = {"clients": {ctx.region: ec}, "global_id": None, "groups": [], "subnet_groups": []}
    ctx.on_cleanup(lambda: _teardown(made))
    subnet_group = _subnet_group(ctx, ec, ctx.network(), made)

    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="sim2real behavioral check: replica-count-limit",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        CacheSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    made["groups"].append((ec, rg_id))
    _wait_replication_group_available(ec, rg_id, timeout_s=_budget_s(ctx, 900.0), ctx=ctx)

    before = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]
    before_member_count = len(before["MemberClusters"])
    assert before_member_count == 1, f"expected a single seed member cluster, got {before_member_count}"

    code, message = _error(
        lambda: ec.increase_replica_count(
            ReplicationGroupId=rg_id, NewReplicaCount=6, ApplyImmediately=True
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == "New replica count must be between 1 and 5 replicas.", message

    # Effect absent: member cluster count and status unchanged.
    after_reject = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]
    assert len(after_reject["MemberClusters"]) == before_member_count, (
        "rejected IncreaseReplicaCount still added member clusters"
    )
    assert after_reject["Status"] == "available", (
        f"rejected IncreaseReplicaCount left the group in status={after_reject['Status']!r}"
    )

    # Positive control: requesting 1 replica (within the 0..5 range) succeeds.
    ec.increase_replica_count(ReplicationGroupId=rg_id, NewReplicaCount=1, ApplyImmediately=True)
    # The group is already 'available' before the call, so the wait is on the settled status
    # AND the added member together.
    grown = _wait_replication_group_available(
        ec, rg_id, timeout_s=_budget_s(ctx, 900.0), members=before_member_count + 1, ctx=ctx
    )
    assert len(grown["MemberClusters"]) == before_member_count + 1, (
        f"expected {before_member_count + 1} member clusters after accepted increase, "
        f"got {len(grown['MemberClusters'])}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"the polled state (last={last!r}): the run budget ended first; "
                           f"not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _replication_group(ec, rg_id):
    groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
    if not groups:
        raise AssertionError(f"replication group {rg_id!r} disappeared unexpectedly")
    return groups[0]


def _wait_replication_group_available(ec, rg_id, timeout_s=900.0, members=None, ctx=None):
    return _poll_until(
        lambda: _replication_group(ec, rg_id),
        lambda group: group["Status"] == "available"
        and (members is None or len(group["MemberClusters"]) == members),
        timeout_s=timeout_s,
        interval_s=2.0,
        ctx=ctx,
    )




#: The teardown's own bound, inside the elasticache suite's 1800 s teardown budget.
_TEARDOWN_S = 1700.0
#: Answers while the global datastore or a member is still settling an earlier change.
_GRG_BUSY = {"InvalidGlobalReplicationGroupState", "InvalidGlobalReplicationGroupStateFault"}
_RG_BUSY = {"InvalidReplicationGroupState", "InvalidReplicationGroupStateFault"}


def _code(err: ClientError) -> str:
    return err.response["Error"]["Code"]


def _subnet_group(ctx, ec, network, made: dict) -> str:
    """A cache subnet group over ``network``'s subnets, in the region ``ec`` signs for."""
    name = ctx.unique_name("sim2real-ec-sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=network.subnet_ids,
    )
    made["subnet_groups"].append((ec, name))
    return name


def _teardown(made: dict) -> None:
    """Delete the global datastore if any, then every replication group, then the subnet groups.

    Every step runs; the raise names each one that failed. ``made["clients"]`` maps a region to
    its client, and each replication group or subnet group is deleted with its own region's.
    """
    deadline = time.monotonic() + _TEARDOWN_S
    failures: list[str] = []
    deleting = []

    def delete(ec, rg_id: str) -> None:
        _delete_rg(ec, rg_id, deadline)
        deleting.append((ec, rg_id))

    steps = []
    if made.get("global_id"):
        steps.append((f"global datastore {made['global_id']}", lambda: _delete_global(made, deadline)))
    steps += [(f"delete {rg_id}", lambda ec=ec, rg_id=rg_id: delete(ec, rg_id)) for ec, rg_id in made["groups"]]
    for label, fn in steps:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - every step runs; the raise names each failure
            failures.append(f"{label}: {type(exc).__name__}: {exc}")
    for ec, rg_id in deleting:
        try:
            _wait_rg_gone(ec, rg_id, deadline)
        except Exception as exc:  # noqa: BLE001 - every step runs; the raise names each failure
            failures.append(f"wait for {rg_id} to go: {type(exc).__name__}: {exc}")
    for ec, name in made["subnet_groups"]:
        try:
            _delete_subnet_group(ec, name, deadline)
        except Exception as exc:  # noqa: BLE001 - every step runs; the raise names each failure
            failures.append(f"subnet group {name}: {type(exc).__name__}: {exc}")
    if failures:
        raise AssertionError(f"teardown left {len(failures)} resource(s): {'; '.join(failures)}")


def _delete_global(made: dict, deadline: float) -> None:
    """Disassociate every secondary through the current primary's region, then delete the group."""
    global_id, clients = made["global_id"], made["clients"]
    while True:
        try:
            grg = next(iter(clients.values())).describe_global_replication_groups(
                GlobalReplicationGroupId=global_id, ShowMemberInfo=True
            )["GlobalReplicationGroups"][0]
        except ClientError as err:
            if _code(err) == "GlobalReplicationGroupNotFoundFault":
                return
            raise
        members = grg.get("Members", [])
        primary = next((m for m in members if m.get("Role") == "PRIMARY"), None)
        ec = clients.get(primary["ReplicationGroupRegion"]) if primary else None
        ec = ec or next(iter(clients.values()))
        try:
            secondaries = [m for m in members if m.get("Role") != "PRIMARY"]
            for m in secondaries:
                if m.get("Status") == "associated":
                    ec.disassociate_global_replication_group(
                        GlobalReplicationGroupId=global_id,
                        ReplicationGroupId=m["ReplicationGroupId"],
                        ReplicationGroupRegion=m["ReplicationGroupRegion"],
                    )
            if not secondaries and grg.get("Status") != "deleting":
                ec.delete_global_replication_group(
                    GlobalReplicationGroupId=global_id, RetainPrimaryReplicationGroup=True
                )
        except ClientError as err:
            if _code(err) == "GlobalReplicationGroupNotFoundFault":
                return
            if _code(err) not in _GRG_BUSY:
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"still {grg.get('Status')!r} with members {members}")
        time.sleep(2)


def _delete_rg(ec, rg_id: str, deadline: float) -> None:
    """Delete a replication group, retrying while it is still settling an earlier change."""
    while True:
        try:
            ec.delete_replication_group(ReplicationGroupId=rg_id)
            return
        except ClientError as err:
            if _code(err) == "ReplicationGroupNotFoundFault":
                return
            if _code(err) not in _RG_BUSY or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_rg_gone(ec, rg_id: str, deadline: float) -> None:
    while True:
        try:
            status = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0][
                "Status"
            ]
        except ClientError as err:
            if _code(err) == "ReplicationGroupNotFoundFault":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"replication group {rg_id} still {status!r}")
        time.sleep(2)


def _delete_subnet_group(ec, name: str, deadline: float) -> None:
    """Delete a cache subnet group once nothing in it remains."""
    while True:
        try:
            ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
            return
        except ClientError as err:
            if _code(err) == "CacheSubnetGroupNotFoundFault":
                return
            if _code(err) != "CacheSubnetGroupInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
