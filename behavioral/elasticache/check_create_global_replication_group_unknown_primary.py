"""create-global-replication-group-unknown-primary."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the botocore Error (code, message). An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected a rejection but the call SUCCEEDED")

CHECK = "create-global-replication-group-unknown-primary"
GROUP = 'overly-permissive'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGlobalReplicationGroup succeeds on an available primary (positive control) but
    rejects the identical call on a well-formed nonexistent primary, leaving no global
    replication group behind for the rejected suffix."""
    ec = ctx.client("elasticache")
    made: dict = {"clients": {ctx.region: ec}, "global_id": None, "groups": [], "subnet_groups": []}
    ctx.on_cleanup(lambda: _teardown(made))
    subnet_group = _subnet_group(ctx, ec, ctx.network(), made)

    primary_id = ctx.unique_name("sim2real-gup-")[:40]
    # Global Datastore only supports instance families "large" and above (M5/M6g/R5/R6g/...);
    # burstable T-family nodes are rejected with InvalidParameterValue.
    ec.create_replication_group(
        ReplicationGroupId=primary_id,
        ReplicationGroupDescription="sim2real unknown-primary positive control",
        Engine="redis",
        CacheNodeType="cache.m5.large",
        NumCacheClusters=1,
        AutomaticFailoverEnabled=False,
        CacheSubnetGroupName=subnet_group,
    )
    made["groups"].append((ec, primary_id))
    _wait_for_rg_status(ec, primary_id, "available", timeout_s=1500, interval_s=20)

    # Positive control: the same call this check will reject succeeds against a real, available
    # primary -- without this, "rejects a missing primary" is indistinguishable from "rejects
    # every CreateGlobalReplicationGroup".
    # A global datastore id suffix must begin with a letter, as every identifier here does.
    good_suffix = ctx.unique_name("gupgood")
    create_resp = ec.create_global_replication_group(
        GlobalReplicationGroupIdSuffix=good_suffix,
        PrimaryReplicationGroupId=primary_id,
        GlobalReplicationGroupDescription="fidelity check positive control",
    )
    good_global_id = create_resp["GlobalReplicationGroup"]["GlobalReplicationGroupId"]
    made["global_id"] = good_global_id
    _wait_for_global_status(ec, good_global_id, "primary-only", timeout_s=600, interval_s=15)

    # Negative: the identical shape of call against a well-formed but nonexistent primary is
    # rejected as an unknown replication group.
    bogus_suffix = ctx.unique_name("gupnope")
    bogus_primary = ctx.unique_name("sim2real-behav-erg-nope-")
    code, message = _error(lambda: ec.create_global_replication_group(
        GlobalReplicationGroupIdSuffix=bogus_suffix,
        PrimaryReplicationGroupId=bogus_primary,
        GlobalReplicationGroupDescription="fidelity check missing primary",
    ))
    assert code == "ReplicationGroupNotFoundFault", f"expected ReplicationGroupNotFoundFault, got {code}: {message!r}"
    assert message == f"Replication group '{bogus_primary}' not found", (
        f"unexpected ReplicationGroupNotFoundFault message {message!r}"
    )

    # Effect absent: an independent list read (not the mutating call's own response) at the
    # destination shows the positive control's group and nothing carrying the rejected suffix.
    all_ids = {
        g["GlobalReplicationGroupId"]
        for page in ec.get_paginator("describe_global_replication_groups").paginate()
        for g in page.get("GlobalReplicationGroups", [])
    }
    assert good_global_id in all_ids, f"positive control {good_global_id!r} missing from {all_ids}"
    assert not any(bogus_suffix in gid for gid in all_ids), (
        f"a global replication group for the rejected suffix {bogus_suffix!r} exists: {all_ids}"
    )


# ===== helpers =====




def _wait_for_rg_status(client, rg_id, target, timeout_s=1500.0, interval_s=20.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = client.describe_replication_groups(ReplicationGroupId=rg_id)
        groups = resp.get("ReplicationGroups", [])
        if groups:
            last = groups[0]["Status"]
            if last == target:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"replication group {rg_id} never reached {target!r}, last saw {last!r}")




def _describe_global(client, global_id: str) -> dict:
    resp = client.describe_global_replication_groups(GlobalReplicationGroupId=global_id)
    groups = resp.get("GlobalReplicationGroups", [])
    if not groups:
        raise AssertionError(f"global replication group {global_id} not found")
    return groups[0]


def _wait_for_global_status(client, global_id, target, timeout_s=600.0, interval_s=15.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _describe_global(client, global_id)["Status"]
        if last == target:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"global replication group {global_id} never reached {target!r}, last saw {last!r}"
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
