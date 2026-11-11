"""gsi-scan-pagination-over-tied-index-sort-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-scan-pagination-over-tied-index-sort-key"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INDEX = "gsi1"
# Index sort-key values that tie four ways each; UTF-8 byte order is X < _x < x.
_RANKS = ["x", "X", "_x"]
_RANK_BYTE_ORDER = ["X", "_x", "x"]


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


def _scan(ddb, table, limit=None):
    """Every item on the GSI via Scan, following LastEvaluatedKey; returns (items, page sizes, LEKs)."""
    kwargs = {"TableName": table, "IndexName": _INDEX}
    if limit is not None:
        kwargs["Limit"] = limit
    items, page_sizes, leks = [], [], []
    while True:
        resp = ddb.scan(**kwargs)
        items.extend(resp["Items"])
        page_sizes.append(len(resp["Items"]))
        lek = resp.get("LastEvaluatedKey")
        if lek is None:
            return items, page_sizes, leks
        leks.append(lek)
        assert len(leks) <= 40, f"GSI scan paging did not end after 40 pages: {leks!r}"
        kwargs["ExclusiveStartKey"] = lek


def _keys(items):
    return [(it["pk"]["S"], it["sk"]["S"]) for it in items]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Limit walk of a GSI Scan over a partition tied on the index sort key returns every item
    exactly once in the same order as an unpaged scan, and each LastEvaluatedKey names exactly
    the table key plus the GSI key.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GSI.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-gsiscantie-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gk", "AttributeType": "S"},
            {"AttributeName": "gs", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [{"AttributeName": "gk", "KeyType": "HASH"}, {"AttributeName": "gs", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    # Index partition G: 12 items, three distinct gs values, each shared by four items.
    expected = set()
    n = 0
    for p in ("p0", "p1", "p2", "p3"):
        for s in ("s0", "s1", "s2"):
            ddb.put_item(TableName=table, Item={
                "pk": {"S": p}, "sk": {"S": s}, "gk": {"S": "G"}, "gs": {"S": _RANKS[n % 3]},
            })
            expected.add((p, s))
            n += 1
    # A second, untied index partition proves cross-partition dedup still holds.
    ddb.put_item(TableName=table, Item={"pk": {"S": "p9"}, "sk": {"S": "s0"}, "gk": {"S": "H"}, "gs": {"S": "x"}})
    expected.add(("p9", "s0"))

    # Index reads are eventually consistent: poll until the whole table holds in the index.
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 60.0)
    while True:
        seen = set(_keys(_scan(ddb, table)[0]))
        if seen == expected:
            break
        assert time.monotonic() < deadline, f"index never held all {len(expected)} items: {seen!r}"
        time.sleep(2)

    unpaged, _, _ = _scan(ddb, table)
    ukeys = _keys(unpaged)
    assert len(ukeys) == len(expected) and set(ukeys) == expected, (
        f"unpaged GSI scan returned {ukeys!r}, expected each of {sorted(expected)!r} once"
    )
    again = _keys(_scan(ddb, table)[0])
    assert again == ukeys, f"repeated unpaged GSI scan changed order: {ukeys!r} then {again!r}"

    g_ranks = [it["gs"]["S"] for it in unpaged if it["gk"]["S"] == "G"]
    want_ranks = [r for r in _RANK_BYTE_ORDER for _ in range(4)]
    assert g_ranks == want_ranks, (
        f"index partition G's sort-key order {g_ranks!r}, expected byte order {want_ranks!r}"
    )

    for limit in (1, 2, 3, 5, 7, 10):
        items, page_sizes, leks = _scan(ddb, table, limit)
        walk = _keys(items)
        assert walk == ukeys, f"Limit={limit} walk {walk!r} != unpaged {ukeys!r}"
        assert max(page_sizes) <= limit and len(leks) >= 1, (
            f"Limit={limit} page sizes {page_sizes!r} did not page as expected"
        )
        for lek in leks:
            assert set(lek) == {"pk", "sk", "gk", "gs"}, (
                f"LastEvaluatedKey {lek!r} must name exactly pk, sk, gk and gs"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
