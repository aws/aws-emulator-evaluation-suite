"""delete-table-source-region-within-24h-of-replica-add-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-table-source-region-within-24h-of-replica-add-rejected"
GROUP = "data-plane"
SERVICES = ["dynamodb"]


def _error_code(fn) -> tuple[str, str]:
    """``(Error.Code, Error.Message)`` ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags(
    "axis:rejection",
    "cap:c4",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """DeleteTable on a global table's source region, right after that region sourced a new
    replica, is refused with a ValidationException naming the 24-hour restriction; the table
    stays ACTIVE. Removing the (non-source) replica region does not need the restriction to lift.
    """
    region1 = ctx.region
    second_region = "us-west-2" if region1 != "us-west-2" else "us-east-1"
    ddb1 = ctx.client("dynamodb")

    table_name = ctx.unique_name("sim2real-behav-gtdr-")
    ddb1.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb1, table_name))
    _wait_table_active(ddb1, table_name)

    _create_replica_with_retry(ddb1, table_name, second_region)
    ctx.on_cleanup(lambda: _remove_replica_then_wait(ddb1, table_name, second_region))
    _poll_until(
        lambda: ddb1.describe_table(TableName=table_name)["Table"],
        lambda d: d["TableStatus"] == "ACTIVE"
        and any(
            r["RegionName"] == second_region and r["ReplicaStatus"] == "ACTIVE"
            for r in d.get("Replicas", [])
        ),
        timeout_s=900,
        interval_s=15,
    )

    code, message = _error_code(lambda: ddb1.delete_table(TableName=table_name))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    assert message == (
        "Replica cannot be deleted because it has acted as a source region for new replica(s) "
        "being added to the table in the last 24 hours."
    ), f"unexpected message for the refused delete: {message!r}"

    after_refusal = ddb1.describe_table(TableName=table_name)["Table"]
    assert after_refusal["TableStatus"] == "ACTIVE", (
        f"table status after the refused delete is {after_refusal['TableStatus']!r}, expected ACTIVE"
    )

    # Positive control: once the table is no longer part of any replication group (the
    # destination replica, which never itself acted as a source, is removed), DeleteTable is an
    # ordinary table delete and is not subject to the source region's 24-hour restriction.
    _remove_replica_then_wait(ddb1, table_name, second_region)
    no_replicas = ddb1.describe_table(TableName=table_name)["Table"]
    assert no_replicas.get("Replicas", []) == [], (
        f"expected no replicas after removing {second_region!r}, got {no_replicas.get('Replicas')!r}"
    )
    ddb1.delete_table(TableName=table_name)
    deleted = _poll_until(
        lambda: _describe_or_none(ddb1, table_name),
        lambda d: d is None or d["TableStatus"] == "DELETING",
        timeout_s=60,
        interval_s=3,
    )
    assert deleted is None or deleted["TableStatus"] == "DELETING", (
        f"table after a delete with no replica attached is {deleted!r}, expected gone or DELETING"
    )


def _describe_or_none(ddb: Any, table_name: str) -> dict | None:
    try:
        return ddb.describe_table(TableName=table_name)["Table"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("ResourceNotFoundException", "TableNotFoundException"):
            return None
        raise


def _wait_table_active(ddb: Any, table_name: str, timeout_s: float = 120) -> None:
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=3,
    )


def _delete_table_ignore(ddb: Any, table_name: str) -> None:
    """DeleteTable, where a table already gone or already being deleted counts as deleted; any
    other refusal, a lingering replica's included, raises."""
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ResourceInUseException" and "Table is being deleted" in err.get(
            "Message", ""
        ):
            return
        if err["Code"] not in ("ResourceNotFoundException", "TableNotFoundException"):
            raise


def _remove_replica_then_wait(ddb1: Any, table_name: str, second_region: str, timeout_s: float = 300.0) -> None:
    """Remove the replica region and wait until DescribeTable lists none, or do nothing if the
    table is already gone or the replica is already removed (ReplicaUpdates Delete on a replica
    that is not there raises a ValidationException naming the missing replica, not a not-found
    code)."""
    current = _describe_or_none(ddb1, table_name)
    if current is None:
        return
    if not any(r["RegionName"] == second_region for r in current.get("Replicas", [])):
        return
    try:
        ddb1.update_table(
            TableName=table_name, ReplicaUpdates=[{"Delete": {"RegionName": second_region}}]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "TableNotFoundException"):
            raise
        return
    _poll_until(
        lambda: _describe_or_none(ddb1, table_name),
        lambda d: d is None or (d["TableStatus"] == "ACTIVE" and not d.get("Replicas")),
        timeout_s=timeout_s,
        interval_s=5,
    )


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
    "security token" message while cross-region replication setup settles -- retry for a bounded
    time rather than treating that as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_table(TableName=table_name, ReplicaUpdates=[{"Create": {"RegionName": region}}])
            return
        except ClientError as exc:
            code = _error_code_from_exc(exc)
            transient = code == "AccessDeniedException" and "security token" in str(exc).lower()
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(
    probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float
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
