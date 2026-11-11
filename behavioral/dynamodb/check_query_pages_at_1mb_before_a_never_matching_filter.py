"""query-pages-at-1mb-before-a-never-matching-filter."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-pages-at-1mb-before-a-never-matching-filter"
GROUP = "pagination"
SERVICES = ["dynamodb"]

# ~50 KB per item -> ~20 items fit in a 1 MB result page, so 40 items must span >= 2 pages.
_ITEM_BYTES = 50 * 1024
_ITEM_COUNT = 40
_ONE_MB = 1024 * 1024
_MAX_PAGES = 12


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _item_bytes(item) -> int:
    """DynamoDB item size for an all-string item: UTF-8 length of each name plus its value."""
    return sum(len(name.encode()) + len(val["S"].encode()) for name, val in item.items())


def _walk(ddb, table, pk, **extra):
    """Every Query page over partition key pk with no Limit, following LastEvaluatedKey."""
    pages = []
    kwargs = {
        "TableName": table,
        "KeyConditionExpression": "pk = :p",
        "ExpressionAttributeValues": {":p": {"S": pk}},
        "ConsistentRead": True,
        **extra,
    }
    while True:
        resp = ddb.query(**kwargs)
        pages.append(resp)
        if "LastEvaluatedKey" not in resp:
            return pages
        assert len(pages) < _MAX_PAGES, f"Query did not end after {_MAX_PAGES} pages"
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query truncates each page at the 1 MB limit before FilterExpression runs: over a partition
    of about 2 MB, a never-matching filter pages at the same two boundaries as the unfiltered
    Query, with Count 0 and the same ScannedCount and LastEvaluatedKey on each page.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddb-qpage1mb-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=t), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    payload = "x" * _ITEM_BYTES
    expected_sks = [f"{i:03d}" for i in range(_ITEM_COUNT)]
    for sk in expected_sks:
        ddb.put_item(TableName=t, Item={"pk": {"S": "big"}, "sk": {"S": sk}, "payload": {"S": payload}})

    # Positive control: the unfiltered Query over the same partition truncates at 1 MB and
    # returns every item exactly once across its pages.
    unfiltered = _walk(ddb, t, "big")
    assert len(unfiltered) == 2, (
        f"a Query over ~{_ITEM_COUNT * _ITEM_BYTES} bytes must span exactly 2 pages, got {len(unfiltered)}"
    )
    for n, page in enumerate(unfiltered, 1):
        assert page["Count"] == page["ScannedCount"] == len(page["Items"]), (
            f"unfiltered page {n}: Count {page['Count']!r} ScannedCount {page['ScannedCount']!r} "
            f"for {len(page['Items'])} items"
        )
    first_bytes = sum(_item_bytes(it) for it in unfiltered[0]["Items"])
    assert first_bytes > _ONE_MB, (
        f"unfiltered page 1 carries a LastEvaluatedKey, so it must have been truncated by the "
        f"1 MB budget and therefore exceed it; got {first_bytes} bytes"
    )
    seen = sorted(it["sk"]["S"] for page in unfiltered for it in page["Items"])
    assert seen == expected_sks, f"unfiltered Query returned {len(seen)} keys, expected {len(expected_sks)}"

    # Main assertion: a never-matching FilterExpression pages at the SAME boundaries, proving the
    # 1 MB limit is applied before the filter rather than after it.
    filtered = _walk(ddb, t, "big", FilterExpression="attribute_exists(no_such_attr)")
    assert len(filtered) == len(unfiltered), (
        f"a never-matching filter must not change the number of pages: unfiltered {len(unfiltered)}, "
        f"filtered {len(filtered)}"
    )
    for n, (u, f) in enumerate(zip(unfiltered, filtered), 1):
        assert f["Count"] == 0 and f["Items"] == [], (
            f"filtered page {n} must carry no matches, got Count={f['Count']} Items={f['Items']!r}"
        )
        assert f["ScannedCount"] == u["ScannedCount"] == u["Count"], (
            f"filtered page {n} ScannedCount {f['ScannedCount']!r} must equal the unfiltered "
            f"page's examined count {u['ScannedCount']!r}"
        )
        assert ("LastEvaluatedKey" in f) == ("LastEvaluatedKey" in u), (
            f"filtered page {n} LastEvaluatedKey presence {('LastEvaluatedKey' in f)!r} must match "
            f"the unfiltered page's {('LastEvaluatedKey' in u)!r}"
        )
        if "LastEvaluatedKey" in f:
            assert f["LastEvaluatedKey"] == u["LastEvaluatedKey"], (
                f"filtered page {n} LastEvaluatedKey {f['LastEvaluatedKey']!r} must equal the "
                f"unfiltered page's {u['LastEvaluatedKey']!r}"
            )

    assert sum(p["ScannedCount"] for p in filtered) == _ITEM_COUNT, (
        f"filtered pages must together scan every item exactly once ({_ITEM_COUNT}); got "
        f"{sum(p['ScannedCount'] for p in filtered)}"
    )
    assert "LastEvaluatedKey" not in filtered[-1], (
        "the last filtered page must reach the end of the partition with no LastEvaluatedKey, "
        f"got {filtered[-1].get('LastEvaluatedKey')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
