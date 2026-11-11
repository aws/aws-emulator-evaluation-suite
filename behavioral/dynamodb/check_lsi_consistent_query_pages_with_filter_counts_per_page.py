"""lsi-consistent-query-pages-with-filter-counts-per-page."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lsi-consistent-query-pages-with-filter-counts-per-page"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INDEX = "by-score"
_PAGE = 4
_ITEMS = 17


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A strongly consistent LSI Query with Limit pages through LastEvaluatedKey (table and index keys)
    in index sort order; with a FilterExpression each page examines exactly Limit items
    (ScannedCount) and returns only matches (Count), so the pages sum to the partition and the filter.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-lsi-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                   {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "score", "AttributeType": "N"},
        ],
        LocalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"},
                          {"AttributeName": "score", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, table))
    _wait_active(ddb, table)

    # Scores are negative, fractional and written out of order; the sort key order differs.
    rows = []
    for i in range(_ITEMS):
        score = f"{(i * 7) % _ITEMS - 8}.{i % 3}" if i % 3 else str((i * 7) % _ITEMS - 8)
        row = {"pk": {"S": "board"}, "sk": {"S": f"z{_ITEMS - i:02d}"}, "score": {"N": score},
               "tier": {"S": "gold" if i % 4 == 0 else "base"}}
        ddb.put_item(TableName=table, Item=row)
        rows.append(row)
    ddb.put_item(TableName=table, Item={"pk": {"S": "other"}, "sk": {"S": "a"}, "score": {"N": "0"},
                                        "tier": {"S": "gold"}})
    by_score = sorted(rows, key=lambda r: float(r["score"]["N"]))
    want_all = [(r["sk"]["S"], r["score"]["N"]) for r in by_score]

    pages = _collect(ddb, table)
    got_all = [p for page in pages for p in page["items"]]
    assert got_all == want_all, f"LSI Query collected {got_all!r}, expected ascending score {want_all!r}"
    assert all(p["scanned"] == len(p["items"]) for p in pages), f"unfiltered pages: {pages!r}"
    assert [p["scanned"] for p in pages] == _page_sizes(_ITEMS), (
        f"expected page sizes {_page_sizes(_ITEMS)} for {_ITEMS} items at Limit={_PAGE}, got {pages!r}"
    )

    fpages = _collect(ddb, table, gold_only=True)
    want_gold = [(r["sk"]["S"], r["score"]["N"]) for r in by_score if r["tier"]["S"] == "gold"]
    assert [p for page in fpages for p in page["items"]] == want_gold, (
        f"filtered LSI Query collected {fpages!r}, expected only the gold rows {want_gold!r}"
    )
    # Limit bounds the items examined before the filter, so page by page the matches are the gold
    # rows among exactly those Limit items.
    sizes = _page_sizes(_ITEMS)
    starts = [sum(sizes[:n]) for n in range(len(sizes))]
    want_pages = [[(r["sk"]["S"], r["score"]["N"]) for r in by_score[s:s + n] if r["tier"]["S"] == "gold"]
                  for s, n in zip(starts, sizes, strict=True)]
    assert [(p["scanned"], p["items"]) for p in fpages] == list(zip(sizes, want_pages, strict=True)), (
        f"filtered pages: expected (ScannedCount, matches) {list(zip(sizes, want_pages, strict=True))!r}, got {fpages!r}"
    )


def _page_sizes(n):
    return [_PAGE] * (n // _PAGE) + ([n % _PAGE] if n % _PAGE else [])


def _collect(ddb, table, *, gold_only=False):
    """Every page of the board partition through the LSI, following LastEvaluatedKey."""
    out, start = [], None
    while True:
        kwargs = {
            "TableName": table, "IndexName": _INDEX, "Limit": _PAGE, "ConsistentRead": True,
            "KeyConditionExpression": "pk = :p",
            "ExpressionAttributeValues": {":p": {"S": "board"}},
        }
        if gold_only:
            kwargs["FilterExpression"] = "tier = :t"
            kwargs["ExpressionAttributeValues"][":t"] = {"S": "gold"}
        if start is not None:
            kwargs["ExclusiveStartKey"] = start
        page = ddb.query(**kwargs)
        items = page["Items"]
        assert page["Count"] == len(items), f"page Count {page['Count']!r} differs from its {len(items)} items"
        out.append({"scanned": page["ScannedCount"],
                    "items": [(i["sk"]["S"], i["score"]["N"]) for i in items]})
        assert len(out) <= 20, "LastEvaluatedKey never ran out after 20 pages"
        start = page.get("LastEvaluatedKey")
        if not start:
            # The final page may end exactly at the partition's end with a key or without one.
            return [p for p in out if p["scanned"]]
        assert set(start) == {"pk", "sk", "score"}, (
            f"an LSI LastEvaluatedKey carries the table and index keys, got {sorted(start)}"
        )


def _wait_active(ddb, table, timeout_s=40.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table)["Table"]
        if last["TableStatus"] == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"table {table} did not become ACTIVE: {last!r}")


def _delete_table_if_exists(ddb, table) -> None:
    try:
        ddb.delete_table(TableName=table)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
