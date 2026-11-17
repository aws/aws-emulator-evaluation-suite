"""query-gsi-two-hash-one-range-key-limit-pages-last-evaluated-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-gsi-two-hash-one-range-key-limit-pages-last-evaluated-key"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INDEX = "by-tenant-region"
_LIMIT = 5
_N_ITEMS = 13


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_active(ddb, table, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table)["Table"]
        indexes = last.get("GlobalSecondaryIndexes", [])
        if last["TableStatus"] == "ACTIVE" and indexes and all(
            g.get("IndexStatus") == "ACTIVE" for g in indexes
        ):
            return
        time.sleep(3)
    raise AssertionError(f"table {table} or its GSI did not become ACTIVE: {last!r}")


def _query(ddb, table, *, limit=None, start=None):
    kwargs = {
        "TableName": table, "IndexName": _INDEX,
        "KeyConditionExpression": "tenant = :t AND #r = :r",
        "ExpressionAttributeNames": {"#r": "region"},
        "ExpressionAttributeValues": {":t": {"S": "acme"}, ":r": {"S": "eu"}},
    }
    if limit is not None:
        kwargs["Limit"] = limit
    if start is not None:
        kwargs["ExclusiveStartKey"] = start
    return ddb.query(**kwargs)


def _key_of(item: dict) -> dict:
    return {"pk": item["pk"], "tenant": item["tenant"], "region": item["region"], "ts": item["ts"]}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Limit-paged Query of a GSI keyed on two HASH attributes and one RANGE attribute pages
    with LastEvaluatedKey carrying the table's key plus all three index key attributes."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-gsi2h1r-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "tenant", "AttributeType": "S"},
            {"AttributeName": "region", "AttributeType": "S"},
            {"AttributeName": "ts", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [
                {"AttributeName": "tenant", "KeyType": "HASH"},
                {"AttributeName": "region", "KeyType": "HASH"},
                {"AttributeName": "ts", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    for i in range(_N_ITEMS):
        ddb.put_item(TableName=table, Item={
            "pk": {"S": f"item-{i:03d}"}, "tenant": {"S": "acme"}, "region": {"S": "eu"},
            "ts": {"S": f"{i:03d}"},
        })
    # One item outside the HASH pair, so the index holds more than the partition under test.
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "item-other"}, "tenant": {"S": "acme"}, "region": {"S": "us"}, "ts": {"S": "000"},
    })

    # The GSI is eventually consistent: poll the unpaged read until all 13 items are visible.
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 60.0)
    while True:
        unpaged = _query(ddb, table)
        if len(unpaged["Items"]) >= _N_ITEMS:
            break
        assert time.monotonic() < deadline, (
            f"the index never held all {_N_ITEMS} items; last read had {len(unpaged['Items'])}"
        )
        time.sleep(2)
    assert len(unpaged["Items"]) == _N_ITEMS, (
        f"expected exactly {_N_ITEMS} items under tenant=acme/region=eu, got {len(unpaged['Items'])}"
    )
    tss = [i["ts"]["S"] for i in unpaged["Items"]]
    assert tss == sorted(tss), f"unpaged GSI Query was not in ascending ts order: {tss!r}"

    # Walk the same query with Limit, following LastEvaluatedKey.
    paged, start, pages, first_lek = [], None, 0, None
    while True:
        page = _query(ddb, table, limit=_LIMIT, start=start)
        items = page["Items"]
        assert len(items) <= _LIMIT, f"page {pages} held {len(items)} items, more than Limit={_LIMIT}"
        paged.extend(items)
        pages += 1
        assert pages <= 20, "LastEvaluatedKey never ran out after 20 pages"
        start = page.get("LastEvaluatedKey")
        if pages == 1:
            first_lek = start
        if not start:
            break
        assert set(start) == {"pk", "tenant", "region", "ts"}, (
            f"page {pages}'s LastEvaluatedKey carries {sorted(start)}, expected exactly the "
            f"table's pk and the index's tenant+region+ts"
        )
        assert start == _key_of(items[-1]), (
            f"page {pages}'s LastEvaluatedKey {start!r} does not name its own last item "
            f"{_key_of(items[-1])!r}"
        )

    expected_pages = -(-_N_ITEMS // _LIMIT)
    assert pages == expected_pages, (
        f"a Limit={_LIMIT} walk of {_N_ITEMS} items took {pages} pages, expected {expected_pages}"
    )
    assert paged == unpaged["Items"], (
        f"the concatenated paged walk {paged!r} differs from the unpaged read {unpaged['Items']!r}"
    )

    # Resuming from the first page's token alone returns exactly the items still owed.
    assert first_lek is not None, "expected a LastEvaluatedKey after the first Limit=5 page"
    rest = _query(ddb, table, start=first_lek)
    assert rest["Items"] == unpaged["Items"][_LIMIT:], (
        f"resuming from the first page's LastEvaluatedKey returned {rest['Items']!r}, expected "
        f"exactly the {len(unpaged['Items']) - _LIMIT} remaining items {unpaged['Items'][_LIMIT:]!r}"
    )
    assert "LastEvaluatedKey" not in rest, (
        f"resuming from the first page straight to the end still carried a LastEvaluatedKey: "
        f"{rest.get('LastEvaluatedKey')!r}"
    )

    # The GSI's answer is backed by real table rows: GetItem on the first and last paged item by
    # the table's own primary key returns the same tenant/region/ts the index reported.
    for item in (unpaged["Items"][0], unpaged["Items"][-1]):
        got = ddb.get_item(TableName=table, Key={"pk": item["pk"]}, ConsistentRead=True)["Item"]
        assert (got["tenant"], got["region"], got["ts"]) == (item["tenant"], item["region"], item["ts"]), (
            f"GetItem on {item['pk']!r} returned tenant={got['tenant']!r} region={got['region']!r} "
            f"ts={got['ts']!r}, expected the GSI's own tenant={item['tenant']!r} region={item['region']!r} "
            f"ts={item['ts']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
