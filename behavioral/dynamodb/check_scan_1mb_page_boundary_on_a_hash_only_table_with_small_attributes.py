"""scan-1mb-page-boundary-on-a-hash-only-table-with-small-attributes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-1mb-page-boundary-on-a-hash-only-table-with-small-attributes"
GROUP = "pagination"
SERVICES = ["dynamodb"]

_ONE_MB = 1024 * 1024
_PAYLOAD_BYTES = 50 * 1024
_UNDER_COUNT = 10
_OVER_COUNT = 30
_MAX_PAGES = 20


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
    return {"pk": {"S": f"item-{i:04d}"}, "v": {"S": "x" * _PAYLOAD_BYTES}}


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


def _batch_put(ddb, table, items) -> None:
    for start in range(0, len(items), 25):
        pending = {table: [{"PutRequest": {"Item": it}} for it in items[start:start + 25]]}
        while True:
            pending = ddb.batch_write_item(RequestItems=pending).get("UnprocessedItems") or {}
            if not pending:
                break


def _walk(ddb, table) -> list:
    """Every Scan page with no Limit, following LastEvaluatedKey."""
    pages, start = [], None
    while True:
        extra = {"ExclusiveStartKey": start} if start else {}
        resp = ddb.scan(TableName=table, ConsistentRead=True, ReturnConsumedCapacity="TOTAL", **extra)
        pages.append(resp)
        start = resp.get("LastEvaluatedKey")
        if not start:
            return pages
        assert len(pages) < _MAX_PAGES, f"Scan did not end after {_MAX_PAGES} pages"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A no-Limit Scan over many hash keys truncates each page at the shortest item prefix
    exceeding 1 MB, Count equals ScannedCount with no filter, and every item is returned exactly
    once across the pages.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbscanhash-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    # Phase 1: 10 items of 50 KB (500 KB total) sit well under the 1 MB budget.
    _batch_put(ddb, table, [_item(i) for i in range(_UNDER_COUNT)])
    resp1 = ddb.scan(TableName=table, ConsistentRead=True, ReturnConsumedCapacity="TOTAL")
    assert "LastEvaluatedKey" not in resp1, (
        f"{_UNDER_COUNT} items of {_PAYLOAD_BYTES} bytes each must fit on one page; got "
        f"LastEvaluatedKey {resp1.get('LastEvaluatedKey')!r}"
    )
    assert resp1["Count"] == resp1["ScannedCount"] == _UNDER_COUNT == len(resp1["Items"]), (
        f"with no FilterExpression Count must equal ScannedCount and the item count; got "
        f"Count={resp1['Count']!r} ScannedCount={resp1['ScannedCount']!r} items={len(resp1['Items'])!r}"
    )
    strong1 = resp1["ConsumedCapacity"]["CapacityUnits"]
    eventual1 = ddb.scan(TableName=table, ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]["CapacityUnits"]
    assert strong1 == 2 * eventual1 and strong1 > 0, (
        f"a strongly consistent scan must cost exactly twice the eventually consistent one; got "
        f"strong={strong1!r} eventual={eventual1!r}"
    )

    # Phase 2: grow to 30 items (1.5 MB total), forcing at least one truncated page.
    _batch_put(ddb, table, [_item(i) for i in range(_UNDER_COUNT, _OVER_COUNT)])
    pages = _walk(ddb, table)
    assert len(pages) >= 2, (
        f"{_OVER_COUNT} items of {_PAYLOAD_BYTES} bytes each ({_OVER_COUNT * _PAYLOAD_BYTES} "
        f"bytes) must not fit on one page; got {len(pages)} page(s)"
    )
    for n, page in enumerate(pages, 1):
        assert page["Count"] == page["ScannedCount"] == len(page["Items"]), (
            f"page {n}: Count={page['Count']!r} ScannedCount={page['ScannedCount']!r} for "
            f"{len(page['Items'])!r} items"
        )
        if "LastEvaluatedKey" in page:
            items = page["Items"]
            total = sum(_item_bytes(it) for it in items)
            without_last = total - _item_bytes(items[-1])
            assert total > _ONE_MB, (
                f"page {n} carries a LastEvaluatedKey, so it was truncated by the 1 MB budget "
                f"and must exceed it; got {total} bytes over {len(items)} items"
            )
            assert without_last <= _ONE_MB, (
                f"page {n} must be the SHORTEST prefix exceeding 1 MB; dropping its last item "
                f"still leaves {without_last} bytes"
            )
    seen = [it["pk"]["S"] for page in pages for it in page["Items"]]
    expected = sorted(f"item-{i:04d}" for i in range(_OVER_COUNT))
    assert sorted(seen) == expected and len(seen) == len(set(seen)), (
        f"paged Scan must return each of the {_OVER_COUNT} items exactly once; got {len(seen)} "
        f"rows, {len(set(seen))} distinct"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
