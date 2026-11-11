"""global-replication-group-secondary-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-replication-group-secondary-lifecycle"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A global replication group's secondary member must be disassociated before
    the group itself can transition to deleted; deleting while a secondary is
    still associated is rejected."""
    ec = ctx.client("elasticache")
    # Global Datastore requires a real cross-region secondary; any pair of distinct
    # regions exercises the contract under test, so which two literals are named is
    # arbitrary -- neither names a region-pinned resource.
    secondary_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    ec2 = ctx.client("elasticache", region=secondary_region)
    # Each region's half sits in that region's shared network.
    made: dict = {
        "clients": {ctx.region: ec, secondary_region: ec2},
        "global_id": None,
        "groups": [],
        "subnet_groups": [],
    }
    ctx.on_cleanup(lambda: _teardown(made))
    primary_sng = _subnet_group(ctx, ec, ctx.network(), made)
    secondary_sng = _subnet_group(ctx, ec2, ctx.network(secondary_region), made)

    primary_id = ctx.unique_name("sim2real-behav-grgp-")
    # Real AWS can refuse the create with InvalidCredentialsException "This action cannot be
    # completed now. Please try again." (HTTP 408): retried as the transient refusal it names.
    _retry_on_transient(
        lambda: ec.create_replication_group(
            ReplicationGroupId=primary_id,
            ReplicationGroupDescription="sim2real global datastore primary",
            Engine="redis",
            # Global Datastore does not support T-family (burstable) node types
            # and requires a Redis engine version that supports it (5.0.6+); use
            # the smallest supported general-purpose type and a modern engine.
            CacheNodeType="cache.m5.large",
            EngineVersion="7.1",
            NumCacheClusters=2,
            AutomaticFailoverEnabled=True,
            CacheSubnetGroupName=primary_sng,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
        {"InvalidCredentialsException"},
        120.0,
    )
    made["groups"].append((ec, primary_id))
    assert _wait_rg_status(ec, primary_id, {"available"}, timeout_s=900) == "available", (
        f"primary replication group {primary_id} did not settle to available"
    )

    suffix = ctx.unique_name("gdssuf").replace("-", "")[:16]
    global_id = ec.create_global_replication_group(
        GlobalReplicationGroupIdSuffix=suffix,
        PrimaryReplicationGroupId=primary_id,
    )["GlobalReplicationGroup"]["GlobalReplicationGroupId"]
    made["global_id"] = global_id

    # Do NOT pre-wait for the global replication group's own 'available' status
    # here: on real AWS that settle is the SAME underlying transition that also
    # gates CreateReplicationGroup(GlobalReplicationGroupId=...) succeeding, so
    # waiting for it up front and then separately waiting for the secondary to
    # provision serializes two waits on one real-world event (and, combined
    # with the multi-minute primary/secondary provisioning this check already
    # pays for, blew the per-check budget). Fold that settle into a bounded
    # retry of the secondary-create call itself instead.
    secondary_id = ctx.unique_name("sim2real-behav-grgs-")
    made["groups"].append((ec2, secondary_id))  # a create that never succeeded deletes as gone
    try:
        _create_secondary_with_retry(
            ec2, secondary_id, global_id, CHECK, secondary_sng, timeout_s=600
        )
    except Exception as exc:
        raise AssertionError(f"could not create secondary replication group in {secondary_region}: {exc}")

    # The secondary shows up as a member (role assigned) essentially as soon as
    # the create call is accepted -- well before it finishes provisioning. The
    # forbidden-deletion behavior under test applies to ANY associated
    # secondary, not only a fully-synced one, so confirm membership/roles
    # without waiting for the secondary's own cluster to reach 'available'.
    members = _wait_member_count(ec, global_id, expected_count=2, timeout_s=180)
    roles = {m["ReplicationGroupId"]: m["Role"] for m in members}
    assert roles[primary_id] == "PRIMARY", f"expected {primary_id} to be PRIMARY, got {roles.get(primary_id)}"
    assert roles[secondary_id] == "SECONDARY", (
        f"expected {secondary_id} to be SECONDARY, got {roles.get(secondary_id)}"
    )

    # Cannot delete the global datastore while the secondary is still associated.
    code, message = _error(
        lambda: ec.delete_global_replication_group(
            GlobalReplicationGroupId=global_id, RetainPrimaryReplicationGroup=True
        )
    )
    # The model names the shape "...StateFault", but ElastiCache sends this code on the wire
    # without the "Fault" suffix, as for this API's other InvalidGlobalReplicationGroupState*
    # rejections.
    assert code == "InvalidGlobalReplicationGroupState", (
        f"expected InvalidGlobalReplicationGroupState deleting {global_id} with an "
        f"associated secondary, got {code}"
    )
    # The message names the datastore's transitional state, which the associate leaves in flux.
    assert message in (
        "Cannot delete a global replication group in creating state",
        "Cannot delete a global replication group in modifying state",
    ), f"unexpected refusal message deleting {global_id}: {message!r}"
    # The forbidden effect did not happen: the group is still there with 2 members.
    # ShowMemberInfo=True is required: without it AWS omits the "Members" key entirely rather
    # than returning an empty list.
    still_there = ec.describe_global_replication_groups(
        GlobalReplicationGroupId=global_id, ShowMemberInfo=True
    )["GlobalReplicationGroups"][0]
    assert still_there["Status"] != "deleted", f"expected not deleted, got status {still_there['Status']}"
    assert len(still_there["Members"]) == 2, f"expected 2 members after rejected delete, got {still_there['Members']}"

    # Disassociation requires the secondary to have finished associating --
    # this is the one real, unavoidable async wait for cross-region sync to
    # settle (there is no way to observe/exercise disassociation without it).
    # Cross-region sync for this node type routinely runs past 15 minutes.
    associated = _wait_global_members(ec, global_id, expected_count=2, timeout_s=1800)
    assert associated, "secondary never reached 'associated' status"

    # Every member reaching 'associated' is necessary but not sufficient: the global
    # datastore's OWN top-level Status can still be settling that same transition
    # (AWS rejects the call with "retry when ... available or primary-only"), so this needs
    # the same bounded retry as the secondary create above.
    _disassociate_with_retry(ec, global_id, secondary_id, secondary_region, timeout_s=300)
    remaining = _wait_global_members(ec, global_id, expected_count=1, timeout_s=600)
    assert remaining[0]["ReplicationGroupId"] == primary_id, (
        f"expected only {primary_id} to remain after disassociation, got {remaining}"
    )
    assert remaining[0]["Role"] == "PRIMARY", f"expected remaining member to be PRIMARY, got {remaining[0]}"

    # Positive control: with the secondary gone, deleting the global datastore now succeeds.
    # Needs the same bounded retry as disassociate above -- the datastore's own top-level
    # Status is still settling the disassociation ("Cannot delete ... in modifying state")
    # even though the member list already shows only the primary.
    _retry_on_transient(
        lambda: ec.delete_global_replication_group(
            GlobalReplicationGroupId=global_id, RetainPrimaryReplicationGroup=True
        ),
        _GRG_TRANSIENT_CODES,
        timeout_s=300,
    )
    deadline = time.monotonic() + 600
    gone = False
    while time.monotonic() < deadline:
        code = _outcome(
            lambda: ec.describe_global_replication_groups(GlobalReplicationGroupId=global_id)
        )
        if code == "GlobalReplicationGroupNotFoundFault":
            gone = True
            break
        time.sleep(2)
    assert gone, "global replication group never transitioned to deleted/404"

    # The now-standalone former secondary's teardown is handled by the
    # registered cleanup (_teardown) -- no need to also delete it here
    # and pay for another synchronous call on the critical path.


# ===== helpers =====

def _wait_rg_status(client, rg_id: str, targets: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        groups = client.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"]
        status = groups[0]["Status"]
        if status in targets:
            return status
        time.sleep(2)
    raise AssertionError(f"replication group {rg_id} never reached {targets}, last status={status}")


# The global datastore's own top-level Status settles asynchronously across every
# state-changing call on it (create, associate, disassociate, delete); real AWS answers
# with one of these two codes -- or, right after creation, the NotFound below -- while
# that settle is still in flight.
_GRG_TRANSIENT_CODES = {"InvalidGlobalReplicationGroupStateFault", "InvalidGlobalReplicationGroupState"}


def _retry_on_transient(fn, transient_codes: set, timeout_s: float):
    """Call *fn*, retrying while it raises one of *transient_codes*, until it succeeds
    or *timeout_s* elapses (then the last error propagates)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in transient_codes or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_secondary_with_retry(
    client, secondary_id: str, global_id: str, check_id: str, subnet_group: str, timeout_s: float
) -> None:
    """Create the secondary replication group, retrying on the transient state
    fault AWS returns while the just-created global datastore is still
    initializing -- this folds that settle time into the (unavoidable) wait
    for the secondary itself, instead of pre-waiting for it separately."""
    # GlobalReplicationGroupNotFoundFault is included here even though the id is valid --
    # the global datastore this check just created has not yet propagated to the secondary
    # region's own control plane, and AWS answers "not found" (not "invalid state") during
    # that lag.
    transient = _GRG_TRANSIENT_CODES | {"InvalidReplicationGroupStateFault", "GlobalReplicationGroupNotFoundFault"}
    _retry_on_transient(
        lambda: client.create_replication_group(
            ReplicationGroupId=secondary_id,
            ReplicationGroupDescription="sim2real global datastore secondary",
            GlobalReplicationGroupId=global_id,
            # The secondary inherits AutomaticFailoverEnabled=True from the global
            # datastore's primary config, which real AWS rejects with
            # InvalidParameterCombination unless NumCacheClusters is explicitly >= 2
            # here too.
            NumCacheClusters=2,
            CacheSubnetGroupName=subnet_group,
            Tags=[{"Key": "sim2real", "Value": check_id}],
        ),
        transient,
        timeout_s,
    )


def _disassociate_with_retry(
    client, global_id: str, secondary_id: str, secondary_region: str, timeout_s: float
) -> None:
    """Disassociate the secondary, retrying on the transient state fault AWS returns
    while the global datastore's own top-level Status is still settling the same
    transition that made every member show 'associated': the bare call is refused even
    once every member reads 'associated'."""
    _retry_on_transient(
        lambda: client.disassociate_global_replication_group(
            GlobalReplicationGroupId=global_id,
            ReplicationGroupId=secondary_id,
            ReplicationGroupRegion=secondary_region,
        ),
        _GRG_TRANSIENT_CODES,
        timeout_s,
    )


def _wait_member_count(client, global_id: str, expected_count: int, timeout_s: float):
    """Wait for the global datastore's member list to reach *expected_count*
    entries with a Role assigned -- WITHOUT requiring each member's Status to
    be fully 'associated'. A secondary appears in this list (role assigned)
    essentially as soon as its create call is accepted, well before its own
    cluster finishes provisioning, and that's all the block-on-deletion
    behavior under test needs."""
    deadline = time.monotonic() + timeout_s
    members = []
    while time.monotonic() < deadline:
        groups = client.describe_global_replication_groups(
            GlobalReplicationGroupId=global_id, ShowMemberInfo=True
        )["GlobalReplicationGroups"]
        members = groups[0].get("Members", [])
        if len(members) >= expected_count and all(m.get("Role") for m in members):
            return members
        time.sleep(5)
    raise AssertionError(f"global replication group {global_id} never reached {expected_count} members, last={members}")


def _wait_global_members(client, global_id: str, expected_count: int, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    members = []
    while time.monotonic() < deadline:
        groups = client.describe_global_replication_groups(
            GlobalReplicationGroupId=global_id, ShowMemberInfo=True
        )["GlobalReplicationGroups"]
        members = groups[0].get("Members", [])
        if len(members) == expected_count and all(m["Status"] == "associated" for m in members):
            return members
        time.sleep(2)
    raise AssertionError(f"global replication group {global_id} never reached {expected_count} members, last={members}")


def _error(fn):
    """The (code, message) of the ClientError fn() raises; an unexpected success fails the check."""
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError("the call unexpectedly succeeded")


def _outcome(fn):
    """Error code of fn() for polling, or "succeeded" while the call still succeeds (not yet deleted)."""
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return "succeeded"


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
