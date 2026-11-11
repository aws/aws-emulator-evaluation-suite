"""global-table-replica-item-replication-round-trip."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-table-replica-item-replication-round-trip"
GROUP = "data-plane"
SERVICES = ["dynamodb"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A global table replicates item writes between its regions: a put, an update and a delete
    issued in either region read back identically, or disappear, in the other. Each region's
    DescribeTable lists the other as an ACTIVE replica throughout.
    """
    region1 = ctx.region
    second_region = "us-west-2" if region1 != "us-west-2" else "us-east-1"
    ddb1 = ctx.client("dynamodb")
    ddb2 = ctx.client("dynamodb", region=second_region)

    table_name = ctx.unique_name("sim2real-behav-gtir-")
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

    _create_replica_with_retry(ddb1, table_name, second_region)
    ctx.on_cleanup(lambda: _remove_replica_then_wait(ddb1, table_name, second_region))

    described1 = _poll_until(
        lambda: ddb1.describe_table(TableName=table_name)["Table"],
        lambda d: d["TableStatus"] == "ACTIVE"
        and any(
            r["RegionName"] == second_region and r["ReplicaStatus"] == "ACTIVE"
            for r in d.get("Replicas", [])
        ),
        timeout_s=900,
        interval_s=15,
    )
    regions1 = {r["RegionName"] for r in described1["Replicas"]}
    assert regions1 == {second_region}, (
        f"DescribeTable in {region1!r} expected replica set {{{second_region!r}}}, got {regions1!r}"
    )

    described2 = _poll_until(
        lambda: ddb2.describe_table(TableName=table_name)["Table"],
        lambda d: d["TableStatus"] == "ACTIVE"
        and any(
            r["RegionName"] == region1 and r["ReplicaStatus"] == "ACTIVE"
            for r in d.get("Replicas", [])
        ),
        timeout_s=300,
        interval_s=10,
    )
    regions2 = {r["RegionName"] for r in described2["Replicas"]}
    assert regions2 == {region1}, (
        f"DescribeTable in {second_region!r} expected replica set {{{region1!r}}}, got {regions2!r}"
    )

    # (1) put in region1 -> read in region2, identical attributes.
    pk = ctx.unique_name("sim2real-item-")
    item = {
        "pk": {"S": pk},
        "attr_s": {"S": "replicated-value"},
        "attr_n": {"N": "42"},
        "attr_bool": {"BOOL": True},
    }
    ddb1.put_item(TableName=table_name, Item=item)
    key = {"pk": {"S": pk}}
    replicated = _poll_for_item(ddb2, table_name, key, timeout_s=120, interval_s=2)
    assert replicated == item, (
        f"item replicated to {second_region!r} is {replicated!r}, expected {item!r}"
    )

    # (2) update in region2 -> read back in region1.
    ddb2.update_item(
        TableName=table_name,
        Key=key,
        UpdateExpression="SET attr_s = :v",
        ExpressionAttributeValues={":v": {"S": "updated-in-second-region"}},
    )
    expected_after_update = dict(item, attr_s={"S": "updated-in-second-region"})
    updated_back = _poll_until(
        lambda: ddb1.get_item(TableName=table_name, Key=key).get("Item"),
        lambda i: i == expected_after_update,
        timeout_s=120,
        interval_s=2,
    )
    assert updated_back == expected_after_update, (
        f"item read back in {region1!r} is {updated_back!r}, expected {expected_after_update!r}"
    )

    # (3) delete in region1 -> absence propagates to region2.
    ddb1.delete_item(TableName=table_name, Key=key)
    _poll_until(
        lambda: ddb2.get_item(TableName=table_name, Key=key).get("Item"),
        lambda i: i is None,
        timeout_s=120,
        interval_s=2,
    )
    still_there = ddb1.get_item(TableName=table_name, Key=key, ConsistentRead=True).get("Item")
    assert still_there is None, f"item still present in {region1!r} after delete: {still_there!r}"


def _poll_for_item(
    ddb: Any, table_name: str, key: dict, *, timeout_s: float, interval_s: float
) -> dict:
    """Poll GetItem (no ConsistentRead: cross-region reads are inherently eventually
    consistent) until the item appears, returning its attribute map."""
    result = _poll_until(
        lambda: ddb.get_item(TableName=table_name, Key=key).get("Item"),
        lambda i: i is not None,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    return result


def _wait_table_active(ddb: Any, table_name: str, timeout_s: float = 120) -> None:
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=3,
    )


def _delete_table_ignore(ddb: Any, table_name: str) -> None:
    """DeleteTable, where a table already gone or already being deleted counts as deleted."""
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
    """Remove the replica region and wait until DescribeTable lists none: DeleteTable refuses a
    table that still has a replica."""
    try:
        ddb1.update_table(
            TableName=table_name, ReplicaUpdates=[{"Delete": {"RegionName": second_region}}]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "TableNotFoundException"):
            raise
        return
    _poll_until(
        lambda: ddb1.describe_table(TableName=table_name)["Table"],
        lambda d: d["TableStatus"] == "ACTIVE" and not d.get("Replicas"),
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
