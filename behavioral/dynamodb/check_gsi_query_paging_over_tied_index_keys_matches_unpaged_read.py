"""gsi-query-paging-over-tied-index-keys-matches-unpaged-read."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-query-paging-over-tied-index-keys-matches-unpaged-read"
GROUP = "query"
SERVICES = ["dynamodb"]

_HASH_ONLY = "by-group"
_WITH_RANGE = "by-group-rank"
# Index sort-key values that tie four ways each; UTF-8 byte order is X < _x < x.
_RANKS = ["x", "X", "_x"]
_RANK_BYTE_ORDER = ["X", "_x", "x"]
_LIMITS = (1, 2, 3, 5)


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


def _read(ddb, table, index, forward, limit=None):
    """Every item of partition G on the index, following LastEvaluatedKey; returns (items, pages)."""
    kwargs = {
        "TableName": table, "IndexName": index, "KeyConditionExpression": "gk = :g",
        "ExpressionAttributeValues": {":g": {"S": "G"}}, "ScanIndexForward": forward,
    }
    if limit is not None:
        kwargs["Limit"] = limit
    items, pages = [], []
    while True:
        resp = ddb.query(**kwargs)
        pages.append(len(resp["Items"]))
        items.extend(resp["Items"])
        if "LastEvaluatedKey" not in resp:
            return items, pages
        assert len(pages) <= 40, f"{index} paging did not end after 40 pages: {pages!r}"
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _keys(items):
    return [(it["pk"]["S"], it["sk"]["S"]) for it in items]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GSI Query over items tying on the index key returns each item once, in byte order of the sort
    key; a Limit 1/2/3/5 walk equals the unpaged read, and ScanIndexForward=False is its mirror.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GSI.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsitie-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gk", "AttributeType": "S"},
            {"AttributeName": "gs", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {"IndexName": _HASH_ONLY, "KeySchema": [{"AttributeName": "gk", "KeyType": "HASH"}],
             "Projection": {"ProjectionType": "ALL"}},
            {"IndexName": _WITH_RANGE,
             "KeySchema": [{"AttributeName": "gk", "KeyType": "HASH"}, {"AttributeName": "gs", "KeyType": "RANGE"}],
             "Projection": {"ProjectionType": "ALL"}},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    # 12 items in index partition G: base sort keys repeat across partitions, ranks tie 4 ways.
    expected = set()
    n = 0
    for p in ("p0", "p1", "p2", "p3"):
        for s in ("s0", "s1", "s2"):
            ddb.put_item(TableName=table, Item={
                "pk": {"S": p}, "sk": {"S": s}, "gk": {"S": "G"}, "gs": {"S": _RANKS[n % 3]},
            })
            expected.add((p, s))
            n += 1
    ddb.put_item(TableName=table, Item={"pk": {"S": "p9"}, "sk": {"S": "s0"}, "gk": {"S": "H"}, "gs": {"S": "x"}})

    # Index reads are eventually consistent: poll until both indexes hold every item.
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 60.0)
    while True:
        seen = {idx: _keys(_read(ddb, table, idx, True)[0]) for idx in (_HASH_ONLY, _WITH_RANGE)}
        if all(set(v) == expected for v in seen.values()):
            break
        assert time.monotonic() < deadline, f"indexes never held all {len(expected)} items: {seen!r}"
        time.sleep(2)

    for index in (_HASH_ONLY, _WITH_RANGE):
        forward, _ = _read(ddb, table, index, True)
        fkeys = _keys(forward)
        assert len(fkeys) == len(expected) and set(fkeys) == expected, (
            f"{index} unpaged forward read returned {fkeys!r}, expected each of {sorted(expected)!r} once"
        )
        again = _keys(_read(ddb, table, index, True)[0])
        assert again == fkeys, f"{index} repeated forward read changed order: {fkeys!r} then {again!r}"
        backward = _keys(_read(ddb, table, index, False)[0])
        assert backward == list(reversed(fkeys)), (
            f"{index} ScanIndexForward=False {backward!r} is not the mirror of forward {fkeys!r}"
        )
        if index == _WITH_RANGE:
            ranks = [it["gs"]["S"] for it in forward]
            want = [r for r in _RANK_BYTE_ORDER for _ in range(4)]
            assert ranks == want, f"{index} sort-key order {ranks!r}, expected byte order {want!r}"
        for limit in _LIMITS:
            for direction, unpaged in ((True, fkeys), (False, backward)):
                items, pages = _read(ddb, table, index, direction, limit)
                walk = _keys(items)
                assert walk == unpaged, (
                    f"{index} Limit={limit} forward={direction} walk {walk!r} != unpaged {unpaged!r}"
                )
                assert max(pages) <= limit and len(pages) >= 2 and pages[1] > 0, (
                    f"{index} Limit={limit} forward={direction} page sizes {pages!r}"
                )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
