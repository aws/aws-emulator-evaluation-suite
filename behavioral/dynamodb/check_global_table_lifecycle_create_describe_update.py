"""global-table-lifecycle-create-describe-update."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "global-table-lifecycle-create-describe-update"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A replica added through UpdateTable ReplicaUpdates shows on DescribeTable as one ACTIVE
    replica in its region with GlobalTableVersion 2019.11.21; removing, re-adding and removing it
    again is reflected on each later DescribeTable."""
    ddb = ctx.client("dynamodb")
    region1 = ctx.region
    region2 = _secondary_region(region1)
    key_schema = [{"AttributeName": "pk", "KeyType": "HASH"}]
    attr_defs = [{"AttributeName": "pk", "AttributeType": "S"}]
    global_name = ctx.unique_name("sim2real-behav-gt-")

    ddb.create_table(
        TableName=global_name,
        AttributeDefinitions=attr_defs,
        KeySchema=key_schema,
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, global_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=global_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )

    # CreateGlobalTable is refused on accounts that use global tables version 2019.11.21 ("DynamoDB
    # global tables version 2019.11.21 must be used to create new global tables"), even for a
    # single-region replication group. UpdateTable's ReplicaUpdates, issued from the table's own
    # region, makes the table global; DynamoDB creates the replica table in the target region.
    #
    # A ReplicaUpdates "Create" issued as soon as the source table (with a newly enabled stream)
    # reaches ACTIVE can be refused with an AccessDeniedException carrying a "security token"
    # message while cross-region replication settles; the create retries that refusal.
    _create_replica_with_retry(ddb, global_name, region2)
    ctx.on_cleanup(lambda: _safe_remove_replica(ddb, global_name, region2))

    # DescribeGlobalTable/UpdateGlobalTable serve only version 2017.11.29 tables and answer
    # GlobalTableNotFoundException for a table made global through ReplicaUpdates, so replica
    # state is read through DescribeTable (Table.Replicas[].ReplicaStatus) and changed through
    # UpdateTable.
    described = _poll_until(
        lambda: ddb.describe_table(TableName=global_name)["Table"],
        lambda table: table["TableStatus"] == "ACTIVE"
        and any(
            r["RegionName"] == region2 and r["ReplicaStatus"] == "ACTIVE"
            for r in table.get("Replicas", [])
        ),
        timeout_s=280,
        interval_s=5,
    )
    regions_present = {r["RegionName"] for r in described.get("Replicas", [])} | {region1}
    assert regions_present == {region1, region2}, (
        f"expected replica set {{{region1!r}, {region2!r}}} after ReplicaUpdates Create, "
        f"got {regions_present!r}"
    )
    _assert_one_active_replica(described, region2)

    # With the table global across two regions, UpdateTable's ReplicaUpdates removes the replica...
    ddb.update_table(
        TableName=global_name,
        ReplicaUpdates=[{"Delete": {"RegionName": region2}}],
    )
    _poll_until(
        lambda: {
            r["RegionName"] for r in ddb.describe_table(TableName=global_name)["Table"].get(
                "Replicas", []
            )
        },
        lambda regions: region2 not in regions,
        timeout_s=280,
        interval_s=5,
    )

    # ...and adds it back. After the region leaves Replicas[], DynamoDB can still be removing the
    # replica's table in region2, and a "Create" for that region is refused with a
    # ValidationException ("Failed to create the new replica ...") until it finishes; the create
    # retries that refusal.
    _create_replica_with_retry(ddb, global_name, region2)
    updated = _poll_until(
        lambda: ddb.describe_table(TableName=global_name)["Table"],
        lambda table: table["TableStatus"] == "ACTIVE"
        and any(
            r["RegionName"] == region2 and r["ReplicaStatus"] == "ACTIVE"
            for r in table.get("Replicas", [])
        ),
        timeout_s=280,
        interval_s=5,
    )
    updated_regions = {r["RegionName"] for r in updated.get("Replicas", [])} | {region1}
    assert updated_regions == {region1, region2}, (
        f"expected replica set {{{region1!r}, {region2!r}}} after remove-then-re-add of "
        f"{region2!r}, got {updated_regions!r}"
    )
    _assert_one_active_replica(updated, region2)

    ddb.update_table(
        TableName=global_name,
        ReplicaUpdates=[{"Delete": {"RegionName": region2}}],
    )
    final = _poll_until(
        lambda: ddb.describe_table(TableName=global_name)["Table"],
        lambda table: table.get("Replicas", []) == [] and table["TableStatus"] == "ACTIVE",
        timeout_s=280,
        interval_s=5,
    )
    assert final.get("Replicas", []) == [], (
        f"DescribeTable Replicas after the second ReplicaUpdates Delete read {final['Replicas']!r}"
    )


def _assert_one_active_replica(table: dict, region: str) -> None:
    """The table's own region is not listed: Replicas holds exactly the added region, ACTIVE."""
    replicas = [(r["RegionName"], r["ReplicaStatus"]) for r in table["Replicas"]]
    assert replicas == [(region, "ACTIVE")], f"DescribeTable Replicas read {table['Replicas']!r}"
    assert table["GlobalTableVersion"] == "2019.11.21", (
        f"DescribeTable GlobalTableVersion is {table['GlobalTableVersion']!r}, not '2019.11.21'"
    )


# ===== helpers =====

def _secondary_region(primary_region: str) -> str:
    """A region distinct from the primary, for a global table replica."""
    # Region literals: a replica lives in a second region, and ctx names only its own.
    return "us-west-2" if primary_region != "us-west-2" else "us-east-1"


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _create_replica_with_retry(
    ddb: Any, table_name: str, region: str, *, timeout_s: float = 120, interval_s: float = 5
) -> None:
    """UpdateTable's ReplicaUpdates "Create" issued right as the source table reaches ACTIVE can
    transiently fail with an AccessDeniedException wrapping an "UnrecognizedClientException"/
    "security token" message while DynamoDB's cross-region replication setup settles. Re-creating
    a JUST-deleted replica for the same region can also transiently fail with a ValidationException
    ("Failed to create the new replica ...") while that region's prior replica table finishes
    tearing down in the background, even though it's already gone from Replicas[]. Retry for a
    bounded time rather than treating either as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_table(TableName=table_name, ReplicaUpdates=[{"Create": {"RegionName": region}}])
            return
        except Exception as exc:  # noqa: BLE001
            code = _error_code_from_exc(exc)
            transient = (
                code == "AccessDeniedException" and "security token" in str(exc).lower()
            ) or (code == "ValidationException" and "failed to create" in str(exc).lower())
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _safe_remove_replica(
    ddb: Any, global_name: str, region: str, *, timeout_s: float = 600, interval_s: float = 5
) -> None:
    """Remove the region's replica and wait until Replicas[] no longer lists it. A replica in
    CREATING/UPDATING is first polled to a deletable state; a DELETING one is only awaited.
    ResourceInUseException retries to the deadline; a missing table is fine; other errors raise."""
    deadline = time.monotonic() + timeout_s

    def replica_status() -> str | None:
        table = ddb.describe_table(TableName=global_name)["Table"]
        for r in table.get("Replicas", []):
            if r["RegionName"] == region:
                if r["ReplicaStatus"] == "DELETING":
                    return "DELETING"
                busy = r["ReplicaStatus"] in ("CREATING", "UPDATING")
                if busy or table["TableStatus"] != "ACTIVE":
                    return "BUSY"
                return r["ReplicaStatus"]
        return None

    try:
        status = _poll_until(
            replica_status,
            lambda s: s != "BUSY",
            timeout_s=max(deadline - time.monotonic(), 1),
            interval_s=interval_s,
        )
        if status is None:
            return
        while status != "DELETING":
            try:
                ddb.update_table(
                    TableName=global_name, ReplicaUpdates=[{"Delete": {"RegionName": region}}]
                )
                break
            except ClientError as exc:
                if (
                    _error_code_from_exc(exc) != "ResourceInUseException"
                    or time.monotonic() >= deadline
                ):
                    raise
                time.sleep(interval_s)
        _poll_until(
            replica_status,
            lambda s: s is None,
            timeout_s=max(deadline - time.monotonic(), 1),
            interval_s=interval_s,
        )
    except ClientError as exc:
        if _error_code_from_exc(exc) != "ResourceNotFoundException":
            raise


def _safe_delete_table(
    ddb: Any, table_name: str, *, timeout_s: float = 180, interval_s: float = 2
) -> None:
    """DeleteTable refuses with ResourceInUseException for 30-180s after a replica delete, even
    though the replica is already gone from Replicas[]: retry that code to a bounded deadline, then
    raise. A table already gone is fine; any other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = _error_code_from_exc(exc)
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

