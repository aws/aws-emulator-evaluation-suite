"""create-global-table-already-exists-rejected."""

from __future__ import annotations

import time
from typing import Any, Callable


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-global-table-already-exists-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a table made global through UpdateTable ReplicaUpdates, the 2017.11.29 CreateGlobalTable fails
    with ValidationException and AWS's exact global-tables-version message and leaves both replica
    regions in place."""
    ddb = ctx.client("dynamodb")
    region1 = ctx.region
    region2 = _secondary_region(region1)
    table_name = ctx.unique_name("sim2real-globaltable-")

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

    # Make the table a genuine (2019.11.21-native) global table first, since accounts that
    # reject CreateGlobalTable outright never let it succeed even once.
    _create_replica_with_retry(ddb, table_name, region2)
    ctx.on_cleanup(lambda: _safe_remove_replica(ddb, table_name, region2))
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
    regions_present = {r["RegionName"] for r in described.get("Replicas", [])} | {
        region1
    }
    assert regions_present == {region1, region2}, (regions_present, {region1, region2})

    def _create_again():
        ddb.create_global_table(
            GlobalTableName=table_name,
            ReplicationGroup=[{"RegionName": region1}, {"RegionName": region2}],
        )

    code, message = _error_code_and_message(_create_again)
    assert code == "ValidationException", (code, message)
    expected_msg = (
        "One or more parameter values were invalid: DynamoDB global tables version 2017.11.29 "
        "is not supported. We recommend using DynamoDB global tables version 2019.11.21, instead "
        "of version 2017.11.29 (Legacy)."
    )
    assert message == expected_msg, f"expected message {expected_msg!r}, got {message!r}"

    # The rejected CreateGlobalTable must be a pure no-op: an independent DescribeTable
    # (not the failed call's own response) confirms the replication group is exactly what
    # it was before the rejected attempt -- neither region dropped nor duplicated.
    unchanged = ddb.describe_table(TableName=table_name)["Table"]
    unchanged_regions = {r["RegionName"] for r in unchanged.get("Replicas", [])} | {
        region1
    }
    assert unchanged_regions == {region1, region2}, (
        unchanged_regions,
        {region1, region2},
    )


def _secondary_region(primary_region: str) -> str:
    """A region distinct from the primary, for a global table replica."""
    return "us-west-2" if primary_region != "us-west-2" else "us-east-1"


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _error_code_and_message(fn: Callable[[], Any]) -> tuple[str | None, str]:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response:
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message", "")
        raise
    raise AssertionError("expected a service error, but the call succeeded")


def _create_replica_with_retry(
    ddb: Any,
    table_name: str,
    region: str,
    *,
    timeout_s: float = 90,
    interval_s: float = 5,
) -> None:
    """UpdateTable's ReplicaUpdates "Create" issued right as the source table reaches ACTIVE can
    transiently fail with an AccessDeniedException wrapping an "UnrecognizedClientException"/
    "security token" message while DynamoDB's cross-region replication setup settles — retry for
    a bounded time rather than treating that as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_table(
                TableName=table_name,
                ReplicaUpdates=[{"Create": {"RegionName": region}}],
            )
            return
        except Exception as exc:  # noqa: BLE001
            transient = (
                _error_code_from_exc(exc) == "AccessDeniedException"
                and "security token" in str(exc).lower()
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _safe_remove_replica(ddb: Any, table_name: str, region: str) -> None:
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
