"""query-reverse-pages-at-1mb-in-descending-key-order."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-reverse-pages-at-1mb-in-descending-key-order"
GROUP = "query"
SERVICES = ["dynamodb"]

_ONE_MB = 1024 * 1024
_COUNT = 45
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


def _walk(ddb, table, forward):
    """Every Query page of partition 'big' with no Limit, following LastEvaluatedKey."""
    kwargs = {
        "TableName": table, "KeyConditionExpression": "pk = :p", "ConsistentRead": True,
        "ExpressionAttributeValues": {":p": {"S": "big"}}, "ScanIndexForward": forward,
    }
    pages = []
    while True:
        resp = ddb.query(**kwargs)
        pages.append(resp)
        if "LastEvaluatedKey" not in resp:
            return pages
        assert len(pages) < _MAX_PAGES, f"Query did not end after {_MAX_PAGES} pages"
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ScanIndexForward=False Query with no Limit over ~2.3 MB pages at 1 MB (within one item),
    each LastEvaluatedKey is its page's last key, and the walk yields every key once, descending.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Query.Pagination.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-qrev1mb-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    payload = "x" * _PAYLOAD
    items = [{"pk": {"S": "big"}, "sk": {"S": f"{i:03d}"}, "payload": {"S": payload}} for i in range(_COUNT)]
    _batch_put(ddb, ctx, table, items)
    ascending = [it["sk"]["S"] for it in items]
    largest = max(_item_bytes(it) for it in items)

    for forward, want in ((False, list(reversed(ascending))), (True, ascending)):
        pages = _walk(ddb, table, forward)
        sizes = [sum(_item_bytes(it) for it in p["Items"]) for p in pages]
        assert len(pages) >= 2, f"forward={forward}: ~{_COUNT * _PAYLOAD} bytes came back in one page: {sizes!r}"
        for n, page in enumerate(pages, 1):
            assert sizes[n - 1] <= _ONE_MB + largest, (
                f"forward={forward} page {n} holds {sizes[n - 1]} bytes, over 1 MB plus one item: {sizes!r}"
            )
            lek = page.get("LastEvaluatedKey")
            if n < len(pages):
                last = page["Items"][-1]
                assert lek == {"pk": last["pk"], "sk": last["sk"]}, (
                    f"forward={forward} page {n} LastEvaluatedKey {lek!r} is not its last item's key"
                )
        got = [it["sk"]["S"] for p in pages for it in p["Items"]]
        assert got == want, (
            f"forward={forward} paged Query returned {got!r}, expected every key once in order {want!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
