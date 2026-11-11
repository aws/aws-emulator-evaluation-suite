"""global-replication-group-lifecycle-full."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-replication-group-lifecycle-full"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Global datastore progresses creating -> available, associates a cross-region
    secondary, scales its node groups out, fails the primary region over to the secondary,
    and status/membership reflect each transition end to end."""
    primary_region = ctx.region
    secondary_region = "us-west-2" if primary_region != "us-west-2" else "us-east-1"
    primary_ec = ctx.client("elasticache")
    secondary_ec = ctx.client("elasticache", region=secondary_region)
    # Each region's half sits in that region's shared network.
    made: dict = {
        "clients": {primary_region: primary_ec, secondary_region: secondary_ec},
        "global_id": None,
        "groups": [],
        "subnet_groups": [],
    }
    ctx.on_cleanup(lambda: _teardown(made))
    primary_sng = _subnet_group(ctx, primary_ec, ctx.network(), made)
    secondary_sng = _subnet_group(ctx, secondary_ec, ctx.network(secondary_region), made)

    primary_id = ctx.unique_name("sim2real-grgp-")[:40]
    secondary_id = ctx.unique_name("sim2real-grgs-")[:40]

    # increase_node_groups_in_global_replication_group (below) is a RESHARD, and real
    # ElastiCache rejects a reshard with InvalidParameterValue ("...only be requested for
    # cluster mode enabled global replication group") unless the primary itself was created
    # cluster-mode-ENABLED -- NumCacheClusters alone (cluster mode disabled) is not enough,
    # and neither is NumNodeGroups alone without a matching `.cluster.on` parameter group.
    # The engine version and its parameter-group family are read off the account rather than
    # hardcoded, so this does not start failing the day ElastiCache deprecates an engine.
    engine_version, family = _newest_redis_family(primary_ec)
    cluster_pg = f"default.{family}.cluster.on"

    # Global Datastore only supports instance families "large" and above (M5/M6g/R5/R6g/...);
    # burstable T-family nodes are rejected with InvalidParameterValue. A cluster-mode-enabled
    # group also rejects an explicit AutomaticFailoverEnabled=False ("Redis with cluster mode
    # enabled cannot be created with auto failover turned off") -- leave it unset and let AWS
    # apply the mode-appropriate default.
    primary_ec.create_replication_group(
        ReplicationGroupId=primary_id,
        ReplicationGroupDescription="sim2real global datastore primary",
        Engine="redis",
        EngineVersion=engine_version,
        CacheNodeType="cache.m5.large",
        NumNodeGroups=1,
        ReplicasPerNodeGroup=0,
        CacheParameterGroupName=cluster_pg,
        CacheSubnetGroupName=primary_sng,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    made["groups"].append((primary_ec, primary_id))
    _wait_for_rg_status(primary_ec, primary_id, "available", timeout_s=_budget_s(ctx, 1800),
                        ctx=ctx)
    primary_rg = primary_ec.describe_replication_groups(ReplicationGroupId=primary_id)["ReplicationGroups"][0]
    assert primary_rg.get("ClusterEnabled") is True, (
        f"primary {primary_id} was created with NumNodeGroups=1 and parameter group "
        f"{cluster_pg!r} but reports ClusterEnabled={primary_rg.get('ClusterEnabled')!r}; the "
        f"later reshard (increase_node_groups_in_global_replication_group) requires cluster "
        f"mode enabled and would fail opaquely without this"
    )

    global_suffix = ctx.unique_name("sim2real-gds-")[:30]
    create_resp = primary_ec.create_global_replication_group(
        GlobalReplicationGroupIdSuffix=global_suffix, PrimaryReplicationGroupId=primary_id
    )
    global_id = create_resp["GlobalReplicationGroup"]["GlobalReplicationGroupId"]
    made["global_id"] = global_id
    # With only the primary cluster as a member, the Global datastore's terminal status is
    # "primary-only" (not "available") -- "available" only appears once a secondary is
    # associated.
    _wait_for_global_status(primary_ec, global_id, "primary-only", timeout_s=_budget_s(ctx, 900),
                            ctx=ctx)

    secondary_ec.create_replication_group(
        ReplicationGroupId=secondary_id,
        ReplicationGroupDescription="sim2real global datastore secondary",
        GlobalReplicationGroupId=global_id,
        CacheSubnetGroupName=secondary_sng,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    made["groups"].append((secondary_ec, secondary_id))
    _wait_for_rg_status(secondary_ec, secondary_id, "available", timeout_s=_budget_s(ctx, 1800),
                        ctx=ctx)

    members = _wait_for_global_member_count(primary_ec, global_id, 2, timeout_s=_budget_s(ctx, 1800),
                                            ctx=ctx)
    roles = {m["ReplicationGroupId"]: m["Role"] for m in members}
    assert roles.get(primary_id) == "PRIMARY", f"expected {primary_id} to be PRIMARY, roles={roles}"
    assert roles.get(secondary_id) == "SECONDARY", f"expected {secondary_id} to be SECONDARY, roles={roles}"
    # The member count reaching 2 does not mean the GRG's own top-level status has settled back
    # from "modifying" to "available" yet -- IncreaseNodeGroupsInGlobalReplicationGroup rejects
    # with InvalidGlobalReplicationGroupState ("retry when ... available or primary-only") if
    # issued while that top-level status is still catching up.
    _wait_for_global_status(primary_ec, global_id, "available", timeout_s=_budget_s(ctx, 900),
                            ctx=ctx)

    primary_ec.increase_node_groups_in_global_replication_group(
        GlobalReplicationGroupId=global_id, NodeGroupCount=2, ApplyImmediately=True
    )
    # The pre-reshard status is already "available", so the wait is on the scaled-out
    # node-group count AND the settled status together.
    node_groups = _wait_for_global_node_group_count(
        primary_ec, global_id, 2, timeout_s=_budget_s(ctx, 1800), ctx=ctx
    )
    assert len(node_groups) == 2, f"expected 2 global node groups after the scale-out, got {node_groups}"

    primary_ec.failover_global_replication_group(
        GlobalReplicationGroupId=global_id,
        PrimaryRegion=secondary_region,
        PrimaryReplicationGroupId=secondary_id,
    )
    # The pre-failover status is already "available", so the wait is on the swapped roles AND
    # the settled status together.
    members_after = _wait_for_global_roles(
        primary_ec, global_id, {secondary_id: "PRIMARY", primary_id: "SECONDARY"},
        timeout_s=_budget_s(ctx, 1200), ctx=ctx,
    )
    roles_after = {m["ReplicationGroupId"]: m["Role"] for m in members_after}
    assert roles_after.get(secondary_id) == "PRIMARY", (
        f"expected {secondary_id} to be PRIMARY after failover, roles={roles_after}"
    )
    assert roles_after.get(primary_id) == "SECONDARY", (
        f"expected {primary_id} to be SECONDARY after failover, roles={roles_after}"
    )


def _newest_redis_family(ec) -> tuple[str, str]:
    """``(engine_version, parameter_group_family)`` for the newest Redis the account can create.

    Derived, never hardcoded: the parameter-group family must match the engine version exactly
    (`redis7` cannot attach to a 6.x cluster), and the set of families an account may use changes
    as ElastiCache deprecates old engines.
    """
    versions: list[dict] = []
    paginator = ec.get_paginator("describe_cache_engine_versions")
    for page in paginator.paginate(Engine="redis"):
        versions.extend(page.get("CacheEngineVersions", []))
    assert versions, "describe_cache_engine_versions reports no 'redis' engine version at all"

    def _key(v: dict) -> tuple[int, int, int]:
        parts = [int(p) if p.isdigit() else 0 for p in str(v.get("EngineVersion", "")).split(".")]
        return tuple((parts + [0, 0, 0])[:3])

    newest = max(versions, key=_key)
    family = newest.get("CacheParameterGroupFamily")
    version = newest.get("EngineVersion")
    assert family and version, (
        f"the newest redis engine version entry is missing EngineVersion or "
        f"CacheParameterGroupFamily: {newest!r}"
    )
    return version, family






def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_rg_status(client, rg_id, target, timeout_s=1800.0, interval_s=2.0, ctx=None) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        resp = client.describe_replication_groups(ReplicationGroupId=rg_id)
        groups = resp.get("ReplicationGroups", [])
        if groups:
            last = groups[0]["Status"]
            if last == target:
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"replication group {rg_id} reaching {target!r}: the run budget ended "
                           f"first; not graded")
    raise AssertionError(f"replication group {rg_id} never reached {target!r}, last saw {last!r}")




def _describe_global(client, global_id: str) -> dict:
    resp = client.describe_global_replication_groups(
        GlobalReplicationGroupId=global_id, ShowMemberInfo=True
    )
    groups = resp.get("GlobalReplicationGroups", [])
    if not groups:
        raise AssertionError(f"global replication group {global_id} not found")
    return groups[0]


def _describe_global_members(client, global_id: str) -> list:
    return _describe_global(client, global_id).get("Members", [])


def _wait_for_global_status(client, global_id, target, timeout_s=900.0, interval_s=2.0,
                            ctx=None) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = _describe_global(client, global_id)["Status"]
        if last == target:
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"global replication group {global_id} reaching {target!r}: the run "
                           f"budget ended first; not graded")
    raise AssertionError(
        f"global replication group {global_id} never reached {target!r}, last saw {last!r}"
    )


def _wait_for_global_member_count(client, global_id, count, timeout_s=1800.0, interval_s=2.0,
                                  ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        members = _describe_global_members(client, global_id)
        last = len(members)
        if last == count:
            return members
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"global replication group {global_id} reaching {count} members: the "
                           f"run budget ended first; not graded")
    raise AssertionError(
        f"global replication group {global_id} never reached {count} members, last saw {last}"
    )


def _wait_for_global_node_group_count(client, global_id, count, timeout_s=1800.0, interval_s=2.0,
                                      ctx=None):
    """The node groups once the datastore is 'available' with exactly ``count`` of them."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        grg = _describe_global(client, global_id)
        node_groups = grg.get("GlobalNodeGroups", [])
        last = (grg.get("Status"), len(node_groups))
        if last == ("available", count):
            return node_groups
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"global replication group {global_id} reaching {count} node groups: "
                           f"the run budget ended first; not graded")
    raise AssertionError(
        f"global replication group {global_id} never reached {count} node groups while "
        f"'available', last saw (status, count)={last}"
    )


def _wait_for_global_roles(client, global_id, want: dict, timeout_s=1200.0, interval_s=2.0,
                           ctx=None):
    """The members once the datastore is 'available' and every id in ``want`` holds its role."""
    deadline = time.monotonic() + timeout_s
    grg = None
    while True:
        grg = _describe_global(client, global_id)
        members = grg.get("Members", [])
        roles = {m["ReplicationGroupId"]: m["Role"] for m in members}
        if grg.get("Status") == "available" and all(roles.get(k) == v for k, v in want.items()):
            return members
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"global replication group {global_id} settling with roles "
                                   f"{want!r}: the run budget ended first; not graded")
            # The role assertions in the body name what did not land.
            return members
        time.sleep(interval_s)




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
