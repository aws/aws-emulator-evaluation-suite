"""keys-only-gsi-query-and-scan-page-by-projected-entry-size-not-base-item-size."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "keys-only-gsi-query-and-scan-page-by-projected-entry-size-not-base-item-size"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INDEX = "idx-keys-only"
_ONE_MB = 1024 * 1024
_ITEMS = 23
_PAYLOAD_BYTES = 48_000
_GROUP_KEY = "G#1"


def _item_bytes(item) -> int:
    """DynamoDB item size for an all-string item: UTF-8 length of each name plus its value."""
    return sum(len(name.encode()) + len(val["S"].encode()) for name, val in item.items())


def _wait_active(ddb, table, timeout_s=120.0) -> None:
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        indexes = desc.get("GlobalSecondaryIndexes", [])
        if desc["TableStatus"] == "ACTIVE" and indexes and all(
            g.get("IndexStatus") == "ACTIVE" for g in indexes
        ):
            return
        time.sleep(2)
    raise AssertionError(f"table {table} or its GSI did not become ACTIVE: {desc!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_full(fn, want, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll ``fn`` (a zero-arg call returning a DynamoDB response) until its Count reaches
    ``want`` or the deadline passes; a GSI is eventually consistent so the first read may be short.
    Returns the response the caller asserts against -- the same call that reached the count.
    """
    deadline = time.monotonic() + timeout_s
    resp = fn()
    while resp["Count"] < want:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not met within {timeout_s}s; last Count={resp['Count']}, want {want}"
            )
        time.sleep(interval_s)
        resp = fn()
    return resp


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A KEYS_ONLY GSI's Query and Scan each page against the size of their own projected entries,
    not the base items, so both return every item in one page with no LastEvaluatedKey even when
    the base items alone exceed the 1 MB page limit that truncates the equivalent base-table Query.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-gsipage-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi1pk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [{"AttributeName": "gsi1pk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "KEYS_ONLY"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    payload = "x" * _PAYLOAD_BYTES
    expected_sks = sorted(f"{i:03d}" for i in range(_ITEMS))
    items = [
        {"pk": {"S": "base"}, "sk": {"S": sk}, "gsi1pk": {"S": _GROUP_KEY}, "payload": {"S": payload}}
        for sk in expected_sks
    ]
    for item in items:
        ddb.put_item(TableName=table, Item=item)

    total_base_bytes = sum(_item_bytes(it) for it in items)
    assert total_base_bytes > _ONE_MB, (
        f"this check's premise requires the base items to exceed the 1 MB page limit; "
        f"{_ITEMS} items totalled {total_base_bytes} bytes"
    )
    keys_only_entry_bytes = sum(
        len(n.encode()) + len(v["S"].encode()) for n, v in
        (("pk", {"S": "base"}), ("sk", {"S": "000"}), ("gsi1pk", {"S": _GROUP_KEY}))
    )
    total_keys_only_bytes = keys_only_entry_bytes * _ITEMS
    assert total_keys_only_bytes < _ONE_MB, (
        f"this check's premise requires the KEYS_ONLY index entries to total under 1 MB; "
        f"{_ITEMS} entries totalled {total_keys_only_bytes} bytes"
    )

    # Positive control: the base-table Query over the SAME items, by the base table's own key,
    # does truncate at 1 MB -- proving the premise that the underlying data really exceeds it.
    base_resp = ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": {"S": "base"}},
        ConsistentRead=True,
    )
    assert "LastEvaluatedKey" in base_resp, (
        f"a base-table Query over {total_base_bytes} bytes must truncate at the 1 MB page limit "
        f"and return a LastEvaluatedKey; got Count={base_resp['Count']} and no LastEvaluatedKey"
    )
    assert base_resp["Count"] < _ITEMS, (
        f"the truncated base-table page must be a strict subset of the {_ITEMS} items, got "
        f"Count={base_resp['Count']}"
    )

    # The index entries must really have converged to all _ITEMS before the no-truncation
    # assertion means anything; the eventual-consistency wait and the final read are one call.
    query_resp = _poll_full(
        lambda: ddb.query(
            TableName=table, IndexName=_INDEX, KeyConditionExpression="gsi1pk = :g",
            ExpressionAttributeValues={":g": {"S": _GROUP_KEY}},
        ),
        _ITEMS, description=f"the {_INDEX!r} GSI holding all {_ITEMS} entries",
    )
    assert query_resp["Count"] == _ITEMS, (
        f"Query on {_INDEX!r} must return all {_ITEMS} index entries once converged, got "
        f"Count={query_resp['Count']}"
    )
    assert "LastEvaluatedKey" not in query_resp, (
        f"a KEYS_ONLY GSI Query bills and pages on its own projected entry size "
        f"({total_keys_only_bytes} bytes), not the {total_base_bytes}-byte base items, so it must "
        f"return all {_ITEMS} entries in one page; got a LastEvaluatedKey after "
        f"{query_resp['Count']} items"
    )
    query_keys = sorted(it["sk"]["S"] for it in query_resp["Items"])
    assert query_keys == expected_sks, (
        f"the GSI Query page must carry every sort key once, got {query_keys!r}"
    )
    query_members = sorted({m for it in query_resp["Items"] for m in it})
    assert query_members == ["gsi1pk", "pk", "sk"], (
        f"a KEYS_ONLY GSI entry carries only the base and index key attributes, got {query_members!r}"
    )

    scan_resp = _poll_full(
        lambda: ddb.scan(TableName=table, IndexName=_INDEX), _ITEMS,
        description=f"a Scan of {_INDEX!r} holding all {_ITEMS} entries",
    )
    assert scan_resp["Count"] == _ITEMS, (
        f"Scan of {_INDEX!r} must return all {_ITEMS} index entries once converged, got "
        f"Count={scan_resp['Count']}"
    )
    assert "LastEvaluatedKey" not in scan_resp, (
        f"a KEYS_ONLY GSI Scan bills and pages on its own projected entry size "
        f"({total_keys_only_bytes} bytes), not the {total_base_bytes}-byte base items, so it must "
        f"return all {_ITEMS} entries in one page; got a LastEvaluatedKey after "
        f"{scan_resp['Count']} items"
    )
    scan_keys = sorted(it["sk"]["S"] for it in scan_resp["Items"])
    assert scan_keys == expected_sks, (
        f"the GSI Scan page must carry every sort key once, got {scan_keys!r}"
    )
    assert scan_resp["ScannedCount"] == scan_resp["Count"], (
        f"a Scan with no FilterExpression must have ScannedCount == Count, got "
        f"ScannedCount={scan_resp['ScannedCount']} Count={scan_resp['Count']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
