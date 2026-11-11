"""scan-pages-at-1mb-with-and-without-never-matching-filter."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-pages-at-1mb-with-and-without-never-matching-filter"
GROUP = "scan"
SERVICES = ["dynamodb"]

_ONE_MB = 1024 * 1024
_BIG = 26
_TINY = 26
_PAYLOAD = 50 * 1024
_MAX_PAGES = 20


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _batch_put(ddb, ctx, table, items):
    """BatchWriteItem in chunks of 25, re-sending UnprocessedItems every 2 s until none remain."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 60.0)
    for start in range(0, len(items), 25):
        pending = {table: [{"PutRequest": {"Item": it}} for it in items[start:start + 25]]}
        while True:
            pending = ddb.batch_write_item(RequestItems=pending).get("UnprocessedItems") or {}
            if not pending:
                break
            assert time.monotonic() < deadline, (
                f"BatchWriteItem left {sum(len(v) for v in pending.values())!r} items unprocessed"
            )
            time.sleep(2)


def _item_bytes(item):
    """Item size for an all-string item: UTF-8 length of each name plus its value."""
    return sum(len(name.encode()) + len(val["S"].encode()) for name, val in item.items())


def _walk(ddb, table, **extra):
    """Every Scan page with no Limit, following LastEvaluatedKey."""
    pages, kwargs = [], {"TableName": table, "ConsistentRead": True, **extra}
    while True:
        resp = ddb.scan(**kwargs)
        pages.append(resp)
        if "LastEvaluatedKey" not in resp:
            return pages
        assert len(pages) < _MAX_PAGES, f"Scan did not end after {_MAX_PAGES} pages"
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Scan with no Limit over ~1.3 MB stops each page at 1 MB (within one item) and returns every
    item once; with a never-matching filter the pages are empty but keep a LastEvaluatedKey.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html#Scan.Pagination
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-scan1mb-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    items = []
    for i in range(_BIG + _TINY):
        payload = "x" * _PAYLOAD if i % 2 == 0 else "t"
        items.append({"pk": {"S": f"i{i:03d}"}, "payload": {"S": payload}})
    _batch_put(ddb, ctx, table, items)
    expected = sorted(it["pk"]["S"] for it in items)
    total = sum(_item_bytes(it) for it in items)
    largest = max(_item_bytes(it) for it in items)

    pages = _walk(ddb, table)
    sizes = [sum(_item_bytes(it) for it in p["Items"]) for p in pages]
    assert len(pages) >= 2 and "LastEvaluatedKey" in pages[0], (
        f"a Scan over {total} bytes must end its first page with a LastEvaluatedKey; page sizes {sizes!r}"
    )
    for n, page in enumerate(pages, 1):
        assert sizes[n - 1] <= _ONE_MB + largest, (
            f"Scan page {n} holds {sizes[n - 1]} bytes, more than 1 MB plus one item; sizes {sizes!r}"
        )
        assert page["ScannedCount"] == page["Count"] == len(page["Items"]), (
            f"Scan page {n} Count {page['Count']!r} ScannedCount {page['ScannedCount']!r} "
            f"for {len(page['Items'])} items"
        )
    got = sorted(it["pk"]["S"] for p in pages for it in p["Items"])
    assert got == expected, f"paged Scan returned {len(got)} keys, expected each of {len(expected)} once: {got!r}"

    filtered = _walk(ddb, table, FilterExpression="attribute_exists(no_such_attr)")
    summary = [(p["Count"], p["ScannedCount"], "LastEvaluatedKey" in p) for p in filtered]
    assert len(filtered) >= 2 and summary[0][2], (
        f"a never-matching filter must not stop the 1 MB paging; pages (Count, ScannedCount, key) {summary!r}"
    )
    assert all(p["Count"] == 0 and p["Items"] == [] for p in filtered), (
        f"a never-matching filter returned items; pages {summary!r}"
    )
    assert sum(p["ScannedCount"] for p in filtered) == len(items), (
        f"filtered pages scanned {sum(s for _, s, _ in summary)} items, expected {len(items)}; pages {summary!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
