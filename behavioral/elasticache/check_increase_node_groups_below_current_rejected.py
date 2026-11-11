"""increase-node-groups-below-current-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "increase-node-groups-below-current-rejected"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """IncreaseNodeGroupsInGlobalReplicationGroup only ever scales a Global datastore up: a
    positive scale-out (2 -> 3 shards) succeeds, but asking to 'increase' to a count below
    the datastore's current shard count is rejected and leaves the shard count untouched."""
    ec = ctx.client("elasticache")
    made: dict = {"clients": {ctx.region: ec}, "global_id": None, "groups": [], "subnet_groups": []}
    ctx.on_cleanup(lambda: _teardown(made))
    subnet_group = _subnet_group(ctx, ec, ctx.network(), made)

    # One shared wall-clock budget for the whole check: the runner's time left (a fixed bound
    # outside a runner), so the sum of every wait below never exceeds the check's own budget,
    # however the real time splits between the create, the link and the grow.
    _budget_start = time.monotonic()
    _CHECK_BUDGET_S = 1760.0

    primary_id = ctx.unique_name("sim2real-ngb-")[:40]
    # ElastiCache reshards only a cluster-mode-enabled Global datastore, which starts with at least
    # 2 shards, a replica per shard and automatic failover on a non-burstable node: so the scale-out
    # is 2 -> 3 and the refused "increase" 3 -> 2.
    ec.create_replication_group(
        ReplicationGroupId=primary_id,
        ReplicationGroupDescription="sim2real node-group-count guard",
        Engine="redis",
        CacheParameterGroupName="default.redis7.cluster.on",
        CacheNodeType="cache.m5.large",
        NumNodeGroups=2,
        ReplicasPerNodeGroup=1,
        AutomaticFailoverEnabled=True,
        CacheSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    made["groups"].append((ec, primary_id))
    # The create and the link get capped waits; the reshard, which provisions the added shard's
    # nodes, gets the rest of the shared budget.
    rg = _wait_for_rg_status(
        ec, primary_id, "available",
        timeout_s=_budget_s(ctx, 800.0), interval_s=2, ctx=ctx,
    )
    assert len(rg["NodeGroups"]) == 2, rg["NodeGroups"]

    global_suffix = ctx.unique_name("sim2real-ngb-")[:30]
    create_resp = ec.create_global_replication_group(
        GlobalReplicationGroupIdSuffix=global_suffix, PrimaryReplicationGroupId=primary_id
    )
    global_id = create_resp["GlobalReplicationGroup"]["GlobalReplicationGroupId"]
    made["global_id"] = global_id
    # With only the primary cluster as a member, the Global datastore's terminal status is
    # "primary-only" (not "available") -- "available" only appears once a secondary is
    # associated.
    grg = _wait_for_global_status(
        ec, global_id, "primary-only",
        timeout_s=_budget_s(ctx, 400.0), interval_s=2, ctx=ctx,
    )
    assert len(grg.get("GlobalNodeGroups", [])) == 2, grg.get("GlobalNodeGroups")

    # Positive control: a genuine scale-out (2 -> 3) succeeds. Status and node-group count are
    # polled together in one wait (not two sequential ones) so the whole remaining budget is
    # available to whichever of the two converges last, instead of splitting it in advance.
    ec.increase_node_groups_in_global_replication_group(
        GlobalReplicationGroupId=global_id, NodeGroupCount=3, ApplyImmediately=True
    )
    grg = _wait_for_global_settled(
        ec, global_id, "primary-only", 3,
        timeout_s=_budget_s(ctx, _CHECK_BUDGET_S - (time.monotonic() - _budget_start) - 30.0),
        interval_s=2, ctx=ctx,
    )
    assert len(grg["GlobalNodeGroups"]) == 3

    # Negative: "increasing" to a count below the current shard count (3 -> 2) is rejected.
    code = _error_code(
        lambda: ec.increase_node_groups_in_global_replication_group(
            GlobalReplicationGroupId=global_id, NodeGroupCount=2, ApplyImmediately=True
        )
    )
    assert code == "InvalidParameterValue", code

    # Effect absent: shard count and status are unchanged by the rejected call.
    grg = _describe_global(ec, global_id)
    assert grg["Status"] == "primary-only"
    assert len(grg.get("GlobalNodeGroups", [])) == 3


def _error_code(fn):
    """The error code fn() raises; an unexpected success fails the check."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError("the call unexpectedly succeeded")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_rg_status(client, rg_id, target, timeout_s=1800.0, interval_s=2.0, ctx=None) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        resp = client.describe_replication_groups(ReplicationGroupId=rg_id)
        groups = resp.get("ReplicationGroups", [])
        if groups:
            last = groups[0]["Status"]
            if last == target:
                return groups[0]
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"replication group {rg_id} reaching {target!r}: the run budget ended "
                           f"first; not graded")
    raise AssertionError(f"replication group {rg_id} never reached {target!r}, last saw {last!r}")


def _describe_global(client, global_id: str) -> dict:
    resp = client.describe_global_replication_groups(GlobalReplicationGroupId=global_id)
    groups = resp.get("GlobalReplicationGroups", [])
    if not groups:
        raise AssertionError(f"global replication group {global_id} not found")
    return groups[0]


def _wait_for_global_status(client, global_id, target, timeout_s=900.0, interval_s=2.0,
                            ctx=None) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        grg = _describe_global(client, global_id)
        last = grg["Status"]
        if last == target:
            return grg
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"global replication group {global_id} reaching {target!r}: the run "
                           f"budget ended first; not graded")
    raise AssertionError(
        f"global replication group {global_id} never reached {target!r}, last saw {last!r}"
    )


def _wait_for_global_settled(client, global_id, target_status, target_count, timeout_s=1800.0, interval_s=2.0,
                             ctx=None):
    deadline = time.monotonic() + timeout_s
    last_status, last_count = None, None
    while True:
        grg = _describe_global(client, global_id)
        last_status = grg["Status"]
        last_count = len(grg.get("GlobalNodeGroups", []))
        if last_status == target_status and last_count == target_count:
            return grg
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"global replication group {global_id} settling at {target_status!r} "
                           f"with {target_count} node groups: the run budget ended first; not "
                           f"graded")
    raise AssertionError(
        f"global replication group {global_id} never reached status={target_status!r} with "
        f"{target_count} node groups, last saw status={last_status!r} count={last_count}"
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
