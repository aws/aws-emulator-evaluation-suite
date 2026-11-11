"""gsi-query-last-evaluated-key-carries-every-table-and-index-key-attribute."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-query-last-evaluated-key-carries-every-table-and-index-key-attribute"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INDEX = "StatusIndex"
_LIMIT = 5
_CUSTOMERS = ("cust-01", "cust-02", "cust-03")
_N_ITEMS = 24


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _wait_active(ddb, table, timeout_s=180.0) -> None:
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
    raise AssertionError(f"table {table} or its index did not become ACTIVE: {last!r}")


def _query_group(ddb, table, *, limit=None, start=None):
    kwargs = {
        "TableName": table, "IndexName": _INDEX,
        "KeyConditionExpression": "#s = :s",
        "ExpressionAttributeNames": {"#s": "Status"},
        "ExpressionAttributeValues": {":s": {"S": "PLACED"}},
    }
    if limit is not None:
        kwargs["Limit"] = limit
    if start is not None:
        kwargs["ExclusiveStartKey"] = start
    return ddb.query(**kwargs)


def _key_of(item: dict) -> dict:
    return {"CustomerId": item["CustomerId"], "OrderId": item["OrderId"],
            "Status": item["Status"], "OrderSeq": item["OrderSeq"]}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query against a GSI with a HASH+RANGE key, on a table with a HASH+RANGE primary key,
    pages with LastEvaluatedKey carrying exactly the table's two key attributes plus the index's
    two; resuming from a page's token returns exactly the items the unpaged read still owes.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-gsilek-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "CustomerId", "KeyType": "HASH"},
                   {"AttributeName": "OrderId", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "CustomerId", "AttributeType": "S"},
            {"AttributeName": "OrderId", "AttributeType": "S"},
            {"AttributeName": "Status", "AttributeType": "S"},
            {"AttributeName": "OrderSeq", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [{"AttributeName": "Status", "KeyType": "HASH"},
                          {"AttributeName": "OrderSeq", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    for i in range(_N_ITEMS):
        ddb.put_item(TableName=table, Item={
            "CustomerId": {"S": _CUSTOMERS[i % len(_CUSTOMERS)]},
            "OrderId": {"S": f"order-{i:03d}"},
            "Status": {"S": "PLACED"},
            "OrderSeq": {"N": str(i)},
        })

    # The GSI is eventually consistent: poll the unpaged read until all 24 items are visible.
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 60.0)
    while True:
        unpaged = _query_group(ddb, table)
        if len(unpaged["Items"]) >= _N_ITEMS:
            break
        assert time.monotonic() < deadline, (
            f"the index never held all {_N_ITEMS} items; last read had {len(unpaged['Items'])}"
        )
        time.sleep(2)
    assert len(unpaged["Items"]) == _N_ITEMS, (
        f"expected exactly {_N_ITEMS} items from the unpaged GSI Query, got {len(unpaged['Items'])}"
    )
    seqs = [int(i["OrderSeq"]["N"]) for i in unpaged["Items"]]
    assert seqs == sorted(seqs), f"unpaged GSI Query was not in ascending OrderSeq order: {seqs!r}"
    assert seqs == list(range(_N_ITEMS)), f"unpaged GSI Query returned OrderSeq values {seqs!r}"

    # Walk the same query with Limit, following LastEvaluatedKey.
    paged, start, pages, first_lek = [], None, 0, None
    while True:
        page = _query_group(ddb, table, limit=_LIMIT, start=start)
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
        assert set(start) == {"CustomerId", "OrderId", "Status", "OrderSeq"}, (
            f"page {pages}'s LastEvaluatedKey carries {sorted(start)}, expected exactly the "
            f"table's CustomerId+OrderId and the index's Status+OrderSeq"
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
    rest = _query_group(ddb, table, start=first_lek)
    assert rest["Items"] == unpaged["Items"][_LIMIT:], (
        f"resuming from the first page's LastEvaluatedKey returned {rest['Items']!r}, expected "
        f"exactly the {len(unpaged['Items']) - _LIMIT} remaining items {unpaged['Items'][_LIMIT:]!r}"
    )
    assert "LastEvaluatedKey" not in rest, (
        f"resuming from the first page straight to the end still carried a LastEvaluatedKey: "
        f"{rest.get('LastEvaluatedKey')!r}"
    )

    # The GSI's answer is backed by real table rows: GetItem on the first and last item by the
    # table's own primary key returns the same Status and OrderSeq the index reported.
    for item in (unpaged["Items"][0], unpaged["Items"][-1]):
        got = ddb.get_item(TableName=table, Key={
            "CustomerId": item["CustomerId"], "OrderId": item["OrderId"],
        }, ConsistentRead=True)["Item"]
        assert got["Status"] == item["Status"] and got["OrderSeq"] == item["OrderSeq"], (
            f"GetItem on {item['CustomerId']!r}/{item['OrderId']!r} returned "
            f"Status={got['Status']!r} OrderSeq={got['OrderSeq']!r}, expected the GSI's own "
            f"Status={item['Status']!r} OrderSeq={item['OrderSeq']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
