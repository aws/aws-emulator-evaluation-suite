"""scan-1mb-page-is-the-minimal-byte-prefix-crossing-the-limit."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-1mb-page-is-the-minimal-byte-prefix-crossing-the-limit"
GROUP = "pagination"
SERVICES = ["dynamodb"]

_ONE_MB = 1024 * 1024
# A single partition (one hash key, many sort keys) scans in a deterministic order, so the exact
# split point is reproducible: each item is sized so that neither adding nor dropping one can land
# the running total exactly on the boundary.
_PK = "shard"
_PER_ITEM = 87_400
_NAME_BYTES = len("pk") + len(_PK) + len("sk") + 3 + len("v")
_PAYLOAD = "x" * (_PER_ITEM - _NAME_BYTES)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _item(i: int) -> dict:
    return {"pk": {"S": _PK}, "sk": {"S": f"{i:03d}"}, "v": {"S": _PAYLOAD}}


def _item_bytes(item: dict) -> int:
    """Item size for an all-string item: UTF-8 length of each name plus its value."""
    return sum(len(n.encode()) + len(v["S"].encode()) for n, v in item.items())


def _wait_active(ddb, table) -> None:
    deadline = time.monotonic() + 270.0
    while time.monotonic() < deadline:
        if ddb.describe_table(TableName=table)["Table"]["TableStatus"] == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"table {table!r} did not become ACTIVE before the deadline")


def _assert_minimal_prefix(resp, label: str) -> None:
    """A truncated Scan page is the shortest prefix of the remaining items exceeding 1 MB: it
    includes the item that crosses the boundary, and dropping that one item would not.
    """
    items = resp["Items"]
    total = sum(_item_bytes(it) for it in items)
    without_last = total - _item_bytes(items[-1])
    assert total > _ONE_MB, (
        f"{label}: a page carrying LastEvaluatedKey was truncated by the 1 MB budget, so its "
        f"bytes must exceed it; got {total} bytes over {len(items)} items"
    )
    assert without_last <= _ONE_MB, (
        f"{label}: dropping the page's last item must bring it back under 1 MB -- the page must "
        f"be the SHORTEST prefix exceeding the budget; without the last item it is still "
        f"{without_last} bytes"
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A no-Limit Scan page is the shortest item prefix exceeding 1 MB -- it includes the item
    that crosses the boundary, Count equals ScannedCount with no filter, and a strongly consistent
    scan costs exactly twice the eventually consistent one at that same boundary.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbscan1mb-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    def units(*, consistent: bool):
        resp = ddb.scan(TableName=table, ConsistentRead=consistent, ReturnConsumedCapacity="TOTAL")
        return resp, resp["ConsumedCapacity"]["CapacityUnits"]

    # Phase 1: 11 items sit just under the 1 MB budget -- one more of this size would cross it.
    for i in range(11):
        ddb.put_item(TableName=table, Item=_item(i))
    under_total = 11 * _PER_ITEM
    assert under_total < _ONE_MB and under_total + _PER_ITEM > _ONE_MB, (
        f"the under-boundary fixture must sit within one item of the limit; got {under_total!r}"
    )
    resp1, strong1 = units(consistent=True)
    assert "LastEvaluatedKey" not in resp1, (
        f"11 items totalling {under_total} bytes (under 1 MB) must fit on one page without "
        f"truncation, got LastEvaluatedKey {resp1.get('LastEvaluatedKey')!r}"
    )
    assert resp1["Count"] == resp1["ScannedCount"] == 11 == len(resp1["Items"]), (
        f"with no FilterExpression Count must equal ScannedCount and the item count; got "
        f"Count={resp1['Count']!r} ScannedCount={resp1['ScannedCount']!r} items={len(resp1['Items'])!r}"
    )
    page1_bytes = sum(_item_bytes(it) for it in resp1["Items"])
    assert page1_bytes == under_total, (
        f"the under-boundary page must return exactly the 11 seeded items, totalling "
        f"{under_total} bytes; got {page1_bytes} bytes"
    )
    _, eventual1 = units(consistent=False)
    assert strong1 == 2 * eventual1 and strong1 > 0, (
        f"a strongly consistent scan must cost exactly twice the eventually consistent one; got "
        f"strong={strong1!r} eventual={eventual1!r}"
    )

    # Phase 2: one more item makes the whole table (now 12 items) cross the budget by less than
    # one item's width -- AWS still hands back a LastEvaluatedKey even though nothing is left.
    ddb.put_item(TableName=table, Item=_item(11))
    resp2, strong2 = units(consistent=True)
    assert "LastEvaluatedKey" in resp2, (
        f"12 items whose total exceeds 1 MB must truncate and carry a LastEvaluatedKey even "
        f"though they are the entire table; got {resp2!r}"
    )
    assert resp2["Count"] == resp2["ScannedCount"] == 12, (
        f"Count={resp2['Count']!r} ScannedCount={resp2['ScannedCount']!r}, expected 12 and 12"
    )
    _assert_minimal_prefix(resp2, "phase 2 (12-item table, single page)")
    resume2 = ddb.scan(TableName=table, ConsistentRead=True, ExclusiveStartKey=resp2["LastEvaluatedKey"])
    assert resume2["Count"] == resume2["ScannedCount"] == 0 and "LastEvaluatedKey" not in resume2, (
        f"resuming from that LastEvaluatedKey must find the table truly exhausted; got "
        f"Count={resume2['Count']!r} LastEvaluatedKey={resume2.get('LastEvaluatedKey')!r}"
    )

    # Phase 3: a 13th item now sits beyond the boundary, so the first page still stops at the
    # shortest prefix exceeding 1 MB and the 13th item is left for a second page.
    ddb.put_item(TableName=table, Item=_item(12))
    resp3, strong3 = units(consistent=True)
    assert "LastEvaluatedKey" in resp3, (
        f"13 items must still truncate on the first page; got {resp3!r}"
    )
    _assert_minimal_prefix(resp3, "phase 3 (13-item table, page 1)")
    resume3 = ddb.scan(TableName=table, ConsistentRead=True, ExclusiveStartKey=resp3["LastEvaluatedKey"])
    assert "LastEvaluatedKey" not in resume3, (
        f"the second page must be the terminal one; got LastEvaluatedKey "
        f"{resume3.get('LastEvaluatedKey')!r}"
    )
    first_keys = {it["sk"]["S"] for it in resp3["Items"]}
    second_keys = {it["sk"]["S"] for it in resume3["Items"]}
    assert not (first_keys & second_keys), (
        f"the two pages must not overlap; shared keys {first_keys & second_keys!r}"
    )
    assert first_keys | second_keys == {f"{i:03d}" for i in range(13)}, (
        f"the two pages together must cover all 13 items exactly once; got "
        f"{sorted(first_keys | second_keys)!r}"
    )
    assert resp3["Count"] + resume3["Count"] == 13, (
        f"Count across both pages must sum to 13; got {resp3['Count']!r} + {resume3['Count']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
