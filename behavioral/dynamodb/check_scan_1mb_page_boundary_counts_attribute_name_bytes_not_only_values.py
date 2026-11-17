"""scan-1mb-page-boundary-counts-attribute-name-bytes-not-only-values."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-1mb-page-boundary-counts-attribute-name-bytes-not-only-values"
GROUP = "pagination"
SERVICES = ["dynamodb"]

_ONE_MB = 1024 * 1024
_PK = "shard"
_PER_ITEM = 87_400
_FIXED = len("pk") + len(_PK) + len("sk") + 3  # pk name+value, sk name+value (3-digit)
_REMAINING = _PER_ITEM - _FIXED - 2  # two single-byte "x" values
_NAME_LEN_A = _REMAINING // 2
_NAME_LEN_B = _REMAINING - _NAME_LEN_A
_ATTR_A = "a" * _NAME_LEN_A
_ATTR_B = "b" * _NAME_LEN_B


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
    """An item whose size comes almost entirely from two long attribute NAMES, not their values."""
    return {"pk": {"S": _PK}, "sk": {"S": f"{i:03d}"}, _ATTR_A: {"S": "x"}, _ATTR_B: {"S": "x"}}


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The 1 MB Scan page budget counts attribute NAME bytes, not only values: items whose size
    is almost entirely long attribute names cross the boundary exactly like equally sized values.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbscanname-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    # 11 items whose two attribute names alone sum to just under the per-item byte target; one
    # more item of this shape would push the table's total past the 1 MB budget.
    under_total = 11 * _PER_ITEM
    assert under_total < _ONE_MB and under_total + _PER_ITEM > _ONE_MB, (
        f"the fixture must sit within one item of the limit; got {under_total!r}"
    )
    for i in range(11):
        ddb.put_item(TableName=table, Item=_item(i))
    resp1 = ddb.scan(TableName=table, ConsistentRead=True, ReturnConsumedCapacity="TOTAL")
    assert "LastEvaluatedKey" not in resp1, (
        f"11 name-dominated items totalling {under_total} bytes must fit on one page; got "
        f"LastEvaluatedKey {resp1.get('LastEvaluatedKey')!r}"
    )
    assert resp1["Count"] == resp1["ScannedCount"] == 11 == len(resp1["Items"]), (
        f"Count={resp1['Count']!r} ScannedCount={resp1['ScannedCount']!r} items={len(resp1['Items'])!r}"
    )
    page1_bytes = sum(_item_bytes(it) for it in resp1["Items"])
    assert page1_bytes == under_total, (
        f"the 11 returned items must total {under_total} bytes of names plus values; got {page1_bytes}"
    )

    # A 12th item makes the whole table's name-dominated size cross the budget by less than one
    # item's width -- the page still truncates and carries a LastEvaluatedKey.
    ddb.put_item(TableName=table, Item=_item(11))
    resp2 = ddb.scan(TableName=table, ConsistentRead=True, ReturnConsumedCapacity="TOTAL")
    assert "LastEvaluatedKey" in resp2, (
        f"12 name-dominated items whose total exceeds 1 MB must truncate even though they are "
        f"the entire table; got {resp2!r}"
    )
    assert resp2["Count"] == resp2["ScannedCount"] == 12, (
        f"Count={resp2['Count']!r} ScannedCount={resp2['ScannedCount']!r}, expected 12 and 12"
    )
    items2 = resp2["Items"]
    total2 = sum(_item_bytes(it) for it in items2)
    without_last2 = total2 - _item_bytes(items2[-1])
    assert total2 > _ONE_MB, (
        f"the truncated page must exceed 1 MB; got {total2} bytes over {len(items2)} items"
    )
    assert without_last2 <= _ONE_MB, (
        f"the page must be the SHORTEST prefix exceeding 1 MB; without its last item it is "
        f"still {without_last2} bytes"
    )
    resume = ddb.scan(TableName=table, ConsistentRead=True, ExclusiveStartKey=resp2["LastEvaluatedKey"])
    assert resume["Count"] == resume["ScannedCount"] == 0 and "LastEvaluatedKey" not in resume, (
        f"resuming from that LastEvaluatedKey must find the table exhausted; got "
        f"Count={resume['Count']!r} LastEvaluatedKey={resume.get('LastEvaluatedKey')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
