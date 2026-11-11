"""concurrent-global-table-replica-update-consistency."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-global-table-replica-update-consistency"
GROUP = "concurrency"
SERVICES = ["dynamodb"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Concurrent UpdateTable ReplicaUpdates that each add the same region to one global table leave
    DescribeTable's Replicas listing that region exactly once: never duplicated, never lost."""
    ddb = ctx.client("dynamodb")
    region1 = ctx.region
    region2 = _secondary_region(region1)
    table_name = ctx.unique_name("sim2real-behav-gtc-")

    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={
            "StreamEnabled": True,
            "StreamViewType": "NEW_AND_OLD_IMAGES",
        },
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )
    ctx.on_cleanup(lambda: _safe_remove_replica(ddb, table_name, region2))
    busy = ("ResourceInUseException", "The resource which you are attempting to change is in use.")
    exists = ("ValidationException", f"Global table with name: '{table_name}' already exists.")

    concurrency = 4
    barrier = threading.Barrier(concurrency)
    outcomes: list[tuple[str, str] | str] = [None] * concurrency  # type: ignore[list-item]

    def _race_add(i: int) -> None:
        barrier.wait()
        outcomes[i] = _attempt_create_replica(ddb, table_name, region2)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(_race_add, range(concurrency)))

    # Every non-transient outcome must be either the accepted create or a genuine "someone else
    # already added/is adding this region" conflict -- never an unrelated error. On the
    # 2019.11.21-native UpdateTable(ReplicaUpdates) surface (unlike the legacy
    # CreateGlobalTable/UpdateGlobalTable trio), real AWS names a losing racer that arrives AFTER
    # another's Create has already taken effect with a generic ValidationException, not the more
    # specific ReplicaAlreadyExistsException. Require the message to actually name the conflict.
    codes = [o if o == "SUCCESS" else o[0] for o in outcomes]
    allowed = {"SUCCESS", "ResourceInUseException", "ValidationException"}
    assert all(c in allowed for c in codes), outcomes
    for o in outcomes:
        if o != "SUCCESS":
            code, message = o
            expected = busy if code == busy[0] else exists
            assert (code, message) == expected, f"losing racer with an unrelated refusal: {o}"
    assert "SUCCESS" in codes, f"no racer's Create was ever accepted: {outcomes}"

    described = _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"],
        lambda table: (
            table["TableStatus"] == "ACTIVE"
            and any(
                r["RegionName"] == region2 and r["ReplicaStatus"] == "ACTIVE"
                for r in table.get("Replicas", [])
            )
        ),
        timeout_s=280,
        interval_s=10,
    )
    replica_regions = [r["RegionName"] for r in described.get("Replicas", [])]
    # No duplicate entries (a corrupted merge of the racing Creates could double-list the
    # region), and no lost entry.
    matching = [r for r in replica_regions if r == region2]
    assert len(matching) == 1, (
        f"expected region {region2!r} exactly once, got {replica_regions!r}"
    )


def _secondary_region(primary_region: str) -> str:
    """A region distinct from the primary, for a global table replica."""
    return "us-west-2" if primary_region != "us-west-2" else "us-east-1"


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _attempt_create_replica(
    ddb: Any,
    table_name: str,
    region: str,
    *,
    timeout_s: float = 30,
    interval_s: float = 3,
) -> str | tuple[str, str]:
    """One racer's attempt to add ``region`` as a replica. A brand-new table's replication setup
    can transiently surface an AccessDeniedException wrapping an "UnrecognizedClientException"/
    "security token" message while unrelated infra settles -- that is NOT a race outcome, so
    retry it briefly. Every OTHER outcome (success, or a genuine "region already exists / table
    busy" conflict from a co-racer) is returned as-is, immediately -- that IS the race outcome
    under test. A failure is returned as ``(code, message)`` so the caller can check the message
    names the actual conflict, not just the code."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_table(
                TableName=table_name,
                ReplicaUpdates=[{"Create": {"RegionName": region}}],
            )
            return "SUCCESS"
        except Exception as exc:  # noqa: BLE001
            code = _error_code_from_exc(exc) or "UNKNOWN_ERROR"
            transient = (
                code == "AccessDeniedException" and "security token" in str(exc).lower()
            )
            if not transient or time.monotonic() >= deadline:
                message = (getattr(exc, "response", None) or {}).get("Error", {}).get("Message")
                return (code, str(exc) if message is None else message)
            time.sleep(interval_s)


def _safe_remove_replica(ddb: Any, table_name: str, region: str, timeout_s: float = 240.0) -> None:
    """Remove the replica and wait until DescribeTable lists none: DeleteTable refuses a table that
    still has a replica it acted as the source for."""
    try:
        ddb.update_table(
            TableName=table_name, ReplicaUpdates=[{"Delete": {"RegionName": region}}]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise
        return
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"],
        lambda table: table["TableStatus"] == "ACTIVE" and not table.get("Replicas"),
        timeout_s=timeout_s,
        interval_s=2,
    )


def _safe_delete_table(ddb: Any, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


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
