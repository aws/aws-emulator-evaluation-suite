"""global-replication-group-lifecycle-full-transition."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-replication-group-lifecycle-full-transition"
GROUP = "state-machine"
SERVICES = ["elasticache"]

_RESOURCE_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": CHECK},
]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Global datastore goes create -> add a cross-region secondary -> disassociate -> delete,
    each stage's status and membership settling before the next call; disassociating the
    primary is refused with InvalidParameterValue and leaves both members in place."""
    primary_region = ctx.region
    secondary_region = "us-west-2" if primary_region != "us-west-2" else "us-east-1"

    # Not a region pin: a Global Datastore secondary must live outside the primary's region.
    ec_primary = ctx.client("elasticache")
    ec_secondary = ctx.client("elasticache", region=secondary_region)
    made: dict = {
        "clients": {primary_region: ec_primary, secondary_region: ec_secondary},
        "global_id": None,
        "groups": [],
        "subnet_groups": [],
    }
    ctx.on_cleanup(lambda: _teardown(made))
    primary_sng = _subnet_group(ctx, ec_primary, ctx.network(), made)
    secondary_sng = _subnet_group(ctx, ec_secondary, ctx.network(secondary_region), made)

    primary_id = ctx.unique_name("sim2real-gdg-pri-")[:40].rstrip("-")
    secondary_id = ctx.unique_name("sim2real-gdg-sec-")[:40].rstrip("-")
    global_suffix = ctx.unique_name("sim2real-gdg-")[:30].rstrip("-")

    ec_primary.create_replication_group(
        ReplicationGroupId=primary_id,
        ReplicationGroupDescription="sim2real global datastore primary",
        Engine="redis",
        # Global Datastore rejects T-family (burstable) node types at
        # CreateGlobalReplicationGroup (InvalidParameterValueException); needs M5+ or similar.
        CacheNodeType="cache.m5.large",
        NumCacheClusters=1,
        CacheSubnetGroupName=primary_sng,
        Tags=_RESOURCE_TAGS,
    )
    made["groups"].append((ec_primary, primary_id))
    _poll_until(
        lambda: _describe_rg(ec_primary, primary_id),
        lambda r: r["Status"] == "available",
        timeout_s=_budget_s(ctx, 600.0),
        interval_s=2.0,
        ctx=ctx,
    )

    global_id = ec_primary.create_global_replication_group(
        GlobalReplicationGroupIdSuffix=global_suffix,
        PrimaryReplicationGroupId=primary_id,
    )["GlobalReplicationGroup"]["GlobalReplicationGroupId"]
    made["global_id"] = global_id
    # With only the primary as a member the terminal status is "primary-only"; "available"
    # is not reachable until a secondary is associated.
    grg = _poll_until(
        lambda: _describe_grg(ec_primary, global_id),
        lambda g: g["Status"] == "primary-only",
        timeout_s=_budget_s(ctx, 600.0),
        interval_s=2.0,
        ctx=ctx,
    )
    assert len(grg["Members"]) == 1, f"expected exactly 1 member right after creation, got {grg['Members']}"

    ec_secondary.create_replication_group(
        ReplicationGroupId=secondary_id,
        ReplicationGroupDescription="sim2real global datastore secondary",
        GlobalReplicationGroupId=global_id,
        CacheSubnetGroupName=secondary_sng,
        Tags=_RESOURCE_TAGS,
    )
    made["groups"].append((ec_secondary, secondary_id))
    # A cross-region secondary can still be 'associating' after 1200 s.
    grg = _poll_until(
        lambda: _describe_grg(ec_primary, global_id),
        lambda g: g["Status"] == "available" and len(g["Members"]) == 2,
        timeout_s=_budget_s(ctx, 1800.0),
        interval_s=2.0,
        ctx=ctx,
    )
    member_regions = {m["ReplicationGroupRegion"] for m in grg["Members"]}
    assert secondary_region in member_regions, f"secondary region missing from members: {grg['Members']}"

    # Disassociating the primary is refused as InvalidParameterValue, not
    # InvalidGlobalReplicationGroupState.
    reject_code, message = _expect_rejected(
        lambda: ec_primary.disassociate_global_replication_group(
            GlobalReplicationGroupId=global_id,
            ReplicationGroupId=primary_id,
            ReplicationGroupRegion=primary_region,
        )
    )
    assert reject_code == "InvalidParameterValue", (
        f"disassociating the PRIMARY member must be rejected, got {reject_code!r}"
    )
    assert message == (
        "Cannot disassociate primary replication group. Primary Replication Group will be "
        "disassociated when you delete the Global Replication Group."
    ), f"unexpected refusal message for disassociating the primary: {message!r}"
    grg = _describe_grg(ec_primary, global_id)
    assert len(grg["Members"]) == 2, "rejected disassociate call must not have removed a member"

    ec_primary.disassociate_global_replication_group(
        GlobalReplicationGroupId=global_id,
        ReplicationGroupId=secondary_id,
        ReplicationGroupRegion=secondary_region,
    )
    grg = _poll_until(
        lambda: _describe_grg(ec_primary, global_id),
        lambda g: len(g["Members"]) == 1,
        timeout_s=_budget_s(ctx, 600.0),
        interval_s=2.0,
        ctx=ctx,
    )
    assert grg["Members"][0]["ReplicationGroupId"] == primary_id, (
        f"expected the sole remaining member to be the primary {primary_id!r}, got {grg['Members']}"
    )

    # A disassociated secondary settles on its own clock, and DeleteReplicationGroup refuses it
    # with InvalidReplicationGroupState until it has.
    _while_busy(ctx, _RG_BUSY, lambda: ec_secondary.delete_replication_group(ReplicationGroupId=secondary_id))
    _poll_until(
        lambda: _outcome(lambda: ec_secondary.describe_replication_groups(ReplicationGroupId=secondary_id)),
        lambda code: code == "ReplicationGroupNotFoundFault",
        timeout_s=_budget_s(ctx, 600.0),
        interval_s=2.0,
        ctx=ctx,
    )

    # RetainPrimaryReplicationGroup=False is rejected: deleting the global group never
    # cascades to the primary, which needs its own delete afterwards.
    _while_busy(ctx, _GRG_BUSY, lambda: ec_primary.delete_global_replication_group(
        GlobalReplicationGroupId=global_id, RetainPrimaryReplicationGroup=True
    ))
    _poll_until(
        lambda: _outcome(lambda: ec_primary.describe_global_replication_groups(GlobalReplicationGroupId=global_id)),
        lambda code: code == "GlobalReplicationGroupNotFoundFault",
        timeout_s=_budget_s(ctx, 600.0),
        interval_s=2.0,
        ctx=ctx,
    )
    _while_busy(ctx, _RG_BUSY, lambda: ec_primary.delete_replication_group(ReplicationGroupId=primary_id))
    _poll_until(
        lambda: _outcome(lambda: ec_primary.describe_replication_groups(ReplicationGroupId=primary_id)),
        lambda code: code == "ReplicationGroupNotFoundFault",
        timeout_s=_budget_s(ctx, 600.0),
        interval_s=2.0,
        ctx=ctx,
    )




def _describe_rg(ec, rg_id: str) -> dict[str, Any]:
    return ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]


def _describe_grg(ec, global_id: str) -> dict[str, Any]:
    return ec.describe_global_replication_groups(GlobalReplicationGroupId=global_id, ShowMemberInfo=True)[
        "GlobalReplicationGroups"
    ][0]


def _outcome(fn):
    """Error code of fn() for polling, or "succeeded" while the call still succeeds (not yet deleted)."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return "succeeded"


def _expect_rejected(fn):
    """fn() must fail with (code, message); an unexpected success raises instead of returning a sentinel."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")






def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _while_busy(ctx, busy: set, call):
    """``call()``, retried while it answers a ``busy`` code because an earlier change is settling."""
    deadline = time.monotonic() + _budget_s(ctx, 600.0)
    while True:
        try:
            return call()
        except ClientError as err:
            if err.response["Error"]["Code"] not in busy or time.monotonic() >= deadline:
                if err.response["Error"]["Code"] in busy and _budget_spent(ctx):
                    raise TimeoutError(f"an earlier change settling past "
                                       f"{err.response['Error']['Code']}: the run budget ended "
                                       f"first; not graded") from err
                raise
        time.sleep(2)


def _poll_until(probe, predicate, timeout_s: float = 600.0, interval_s: float = 2.0, ctx=None):
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
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


#: The teardown's own bound.
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
