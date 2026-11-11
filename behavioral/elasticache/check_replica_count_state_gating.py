"""replica-count-state-gating."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replica-count-state-gating"
GROUP = "state-machine"
SERVICES = ["elasticache"]

_NOT_AVAILABLE_MESSAGE = "Replication group must be in available state to modify."


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """IncreaseReplicaCount/DecreaseReplicaCount require the replication group to be
    'available' and drive it into a 'modifying' state that blocks further concurrent
    replica-count changes until the first one completes."""
    ec = ctx.client("elasticache")
    rg_id = ctx.unique_name("sim2real-repl-")
    made: dict = {"clients": {ctx.region: ec}, "global_id": None, "groups": [], "subnet_groups": []}
    ctx.on_cleanup(lambda: _teardown(made))
    subnet_group = _subnet_group(ctx, ec, ctx.network(), made)

    ec.create_replication_group(
        ReplicationGroupId=rg_id,
        ReplicationGroupDescription="replica count gating check",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        AutomaticFailoverEnabled=False,
        CacheSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    made["groups"].append((ec, rg_id))
    _wait_for_rg_status(ec, rg_id, {"available"}, timeout_s=_budget_s(ctx, 1200), ctx=ctx)

    # Sequential gating: IncreaseReplicaCount succeeds and immediately moves the group
    # into 'modifying', which blocks a follow-up DecreaseReplicaCount call.
    ec.increase_replica_count(ReplicationGroupId=rg_id, NewReplicaCount=1, ApplyImmediately=True)
    code, message = _error(
        lambda: ec.decrease_replica_count(
            ReplicationGroupId=rg_id, NewReplicaCount=0, ApplyImmediately=True
        )
    )
    assert code == "InvalidReplicationGroupState", code
    assert message == _NOT_AVAILABLE_MESSAGE, f"expected message {_NOT_AVAILABLE_MESSAGE!r}, got {message!r}"
    # The top-level Status can flip back to 'available' a moment before the newly-added
    # replica actually lands in NodeGroupMembers (the member list update lags the group-level
    # status transition on real ElastiCache), so poll for BOTH conditions together rather than
    # trusting a single describe right after Status == 'available'.
    rg = _wait_for_member_count(ec, rg_id, 2, timeout_s=_budget_s(ctx, 1500), ctx=ctx)
    assert len(rg["NodeGroups"][0]["NodeGroupMembers"]) == 2, rg["NodeGroups"]

    # Concurrency: fire an increase and a decrease at (almost) the same instant. Exactly
    # one racer must win the state transition; the other must be rejected because the
    # group is no longer 'available' by the time it is processed.
    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_inc = pool.submit(
            ec.increase_replica_count,
            ReplicationGroupId=rg_id,
            NewReplicaCount=2,
            ApplyImmediately=True,
        )
        fut_dec = pool.submit(
            ec.decrease_replica_count,
            ReplicationGroupId=rg_id,
            NewReplicaCount=0,
            ApplyImmediately=True,
        )
        outcomes = []
        messages = []
        for fut in (fut_inc, fut_dec):
            try:
                fut.result()
                outcomes.append(None)
                messages.append(None)
            except ClientError as e:
                outcomes.append(e.response["Error"]["Code"])
                messages.append(e.response["Error"].get("Message"))

    successes = [o for o in outcomes if o is None]
    failures = [o for o in outcomes if o is not None]
    assert len(successes) == 1, f"expected exactly one racer to win, got outcomes={outcomes}"
    assert len(failures) == 1 and failures[0] == "InvalidReplicationGroupState", outcomes
    loser_message = next(m for o, m in zip(outcomes, messages) if o is not None)
    assert loser_message == _NOT_AVAILABLE_MESSAGE, (
        f"expected message {_NOT_AVAILABLE_MESSAGE!r}, got {loser_message!r}"
    )

    # The winner's target member count must actually land -- a race-corrupted or
    # silently-ignored loser would leave a different count than the winner alone implies.
    increase_won = outcomes[0] is None
    expected_members = 3 if increase_won else 1
    rg = _wait_for_member_count(ec, rg_id, expected_members, timeout_s=_budget_s(ctx, 1500),
                                ctx=ctx)
    assert len(rg["NodeGroups"][0]["NodeGroupMembers"]) == expected_members, (
        f"final member count does not match the winning racer ({'increase' if increase_won else 'decrease'}); "
        f"got {rg['NodeGroups']}"
    )

    # Positive control: without this, the two InvalidReplicationGroupState rejections above
    # would be indistinguishable from a target where the *loser's* operation never works at all.
    # Whichever racer lost is the one still unproven -- and only that one, since the winner
    # already succeeded above and IncreaseReplicaCount succeeding once already (sequentially,
    # before the race) covers the increase side. Act from the current stable state only:
    # ElastiCache can reject an immediate re-add of a just-removed replica slot with
    # InvalidCacheClusterState, so this never removes-then-recreates the same member.
    if increase_won:
        # decrease lost the race and has not succeeded anywhere in this check yet -- prove it
        # works from the current 3-member state by removing the newest member only.
        ec.decrease_replica_count(ReplicationGroupId=rg_id, NewReplicaCount=1, ApplyImmediately=True)
        final_rg = _wait_for_member_count(ec, rg_id, 2, timeout_s=_budget_s(ctx, 1500), ctx=ctx)
        assert len(final_rg["NodeGroups"][0]["NodeGroupMembers"]) == 2, (
            f"DecreaseReplicaCount did not take effect once the group was available; "
            f"got {final_rg['NodeGroups']}"
        )
    # else: decrease won the race above, which is itself the positive control for decrease --
    # and the sequential IncreaseReplicaCount earlier already covers increase.


def _error(fn):
    """Call fn(); return (code, message) from the ClientError it must raise. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_rg_status(ec, rg_id, targets, timeout_s=1200.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        if groups:
            last = groups[0]["Status"]
            if last in targets:
                return groups[0]
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"replication group {rg_id} reaching {targets}: the run budget ended "
                           f"first; not graded")
    raise AssertionError(f"replication group {rg_id} never reached {targets}, last status={last}")


def _wait_for_member_count(ec, rg_id, expected, timeout_s=1500.0, interval_s=2.0, settle_s=3.0,
                           ctx=None):
    # A single describe that reports 'available' -- at the group level, the member-list level, or
    # the individual-cluster level -- is not proof the state has actually settled: ElastiCache can
    # report a cache cluster 'available' and still reject the very next IncreaseReplicaCount
    # against that same cluster with InvalidCacheClusterState a few hundred ms later. So require the full ready condition to hold on two consecutive polls,
    # settle_s apart, before trusting it.
    deadline = time.monotonic() + timeout_s
    last = None
    consecutive_ready = 0
    while time.monotonic() < deadline:
        groups = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        if groups:
            rg = groups[0]
            last = rg
            members = rg["NodeGroups"][0]["NodeGroupMembers"]
            ready = rg["Status"] == "available" and len(members) == expected and _all_clusters_available(
                ec, [m["CacheClusterId"] for m in members]
            )
            if ready:
                consecutive_ready += 1
                if consecutive_ready >= 2:
                    return rg
                time.sleep(settle_s)
                continue
        consecutive_ready = 0
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"replication group {rg_id} settling at {expected} members: the run "
                           f"budget ended first; not graded")
    raise AssertionError(
        f"replication group {rg_id} never settled at {expected} node group members "
        f"while available (with every underlying cache cluster itself available) across two "
        f"consecutive polls; last={last}"
    )


def _all_clusters_available(ec, cluster_ids):
    # The replication-group-level Status and NodeGroupMembers count can both read as converged
    # while an individual underlying CacheCluster is still settling (a follow-up
    # IncreaseReplicaCount can hit InvalidCacheClusterState on a member that the group-level
    # view already calls 'available'), so require every member's own cluster status too.
    for cid in cluster_ids:
        cluster = ec.describe_cache_clusters(CacheClusterId=cid)["CacheClusters"][0]
        if cluster["CacheClusterStatus"] != "available":
            return False
    return True




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
