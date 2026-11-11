"""global-table-create-describe-update-list."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-table-create-describe-update-list"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new table has no replicas and is listed; adding a replica region with UpdateTable ReplicaUpdates makes
    DescribeTable report both regions and ListTables in the second region list the table. UpdateTable replicas are
    the current (version 2019.11.21) global table mechanism; CreateGlobalTable serves only version 2017.11.29.
    """
    primary_region = ctx.region
    # Concrete, real AWS region names, not a stand-in for a genuinely global or region-pinned
    # resource: a global-table replica MUST live in some second real region, and there is no way
    # to derive "some other region" from ctx alone.
    second_region = "us-west-2" if primary_region != "us-west-2" else "us-east-1"

    ddb1 = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-gt-")
    key_schema = [{"AttributeName": "pk", "KeyType": "HASH"}]
    attr_defs = [{"AttributeName": "pk", "AttributeType": "S"}]

    ddb1.create_table(
        TableName=table_name,
        AttributeDefinitions=attr_defs,
        KeySchema=key_schema,
        BillingMode="PAY_PER_REQUEST",
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb1, table_name))
    _wait_table_active(ddb1, table_name)

    # Before joining a global table, the table has no replicas and is a
    # perfectly normal (single-region) table.
    described = ddb1.describe_table(TableName=table_name)["Table"]
    assert described.get("Replicas", []) == [], f"expected no replicas yet, got {described.get('Replicas')}"

    listed = _table_names(ddb1)
    assert table_name in listed, f"expected {table_name} in ListTables, got absence"

    ddb2 = ctx.client("dynamodb", region=second_region)

    _create_replica_with_retry(ddb1, table_name, second_region)
    ctx.on_cleanup(lambda: _remove_replica_then_delete(ddb1, table_name, second_region))

    described_after = _poll_until(
        lambda: ddb1.describe_table(TableName=table_name)["Table"],
        lambda d: len(d.get("Replicas", [])) == 1
        and all(r["ReplicaStatus"] == "ACTIVE" for r in d["Replicas"]),
        timeout_s=900,
        interval_s=15,
    )
    regions = {r["RegionName"] for r in described_after["Replicas"]}
    expected_regions = {second_region}
    assert regions == expected_regions, f"expected replica set {expected_regions}, got {regions}"

    listed_after = _table_names(ddb2)
    assert table_name in listed_after, f"expected auto-provisioned replica {table_name} in ListTables for {second_region}"


def _table_names(ddb) -> list[str]:
    """Every table name in the client's region, read through all ListTables pages."""
    names: list[str] = []
    for page in ddb.get_paginator("list_tables").paginate():
        names.extend(page["TableNames"])
    return names


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _wait_table_active(ddb, table_name: str, timeout_s: float = 120) -> None:
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=3,
    )


def _delete_table_ignore(ddb, table_name: str) -> None:
    """DeleteTable, where a table already gone or already being deleted counts as deleted."""
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ResourceInUseException" and "Table is being deleted" in err.get("Message", ""):
            return
        if err["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _remove_replica_then_delete(ddb1, table_name: str, second_region: str) -> None:
    # Removing a replica region via UpdateTable also tears down the
    # underlying table AWS auto-provisioned in that region, so only the
    # primary-region table needs an explicit DeleteTable afterwards.
    try:
        ddb1.update_table(
            TableName=table_name,
            ReplicaUpdates=[{"Delete": {"RegionName": second_region}}],
        )
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            try:
                desc = ddb1.describe_table(TableName=table_name)["Table"]
                if all(r["RegionName"] != second_region for r in desc.get("Replicas", [])):
                    break
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ResourceNotFoundException",
                    "TableNotFoundException",
                ):
                    raise
                break
            time.sleep(5)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise
    _delete_table_ignore(ddb1, table_name)


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
    "security token" message while DynamoDB's cross-region replication setup settles -- retry for a
    bounded time rather than treating that as a hard failure. A DIFFERENT AccessDeniedException, one
    that names the AWSServiceRoleForDynamoDBReplication service-linked role directly, means the
    account's own permission boundary denies that role the access it needs, and a global-table
    replica genuinely cannot be provisioned under that restriction -- that one is not transient and
    becomes the check's own assertion."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_table(TableName=table_name, ReplicaUpdates=[{"Create": {"RegionName": region}}])
            return
        except ClientError as exc:
            code = _error_code_from_exc(exc)
            if code == "AccessDeniedException" and "AWSServiceRoleForDynamoDBReplication" in str(exc):
                raise AssertionError(
                    f"account denies the AWSServiceRoleForDynamoDBReplication service-linked "
                    f"role the permissions it needs to provision a global-table replica: {exc}"
                ) from exc
            transient = code == "AccessDeniedException" and "security token" in str(exc).lower()
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

