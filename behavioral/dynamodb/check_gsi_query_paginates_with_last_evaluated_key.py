"""gsi-query-paginates-with-last-evaluated-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-query-paginates-with-last-evaluated-key"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INDEX = "by-owner"
_PAGE = 7
_ITEMS = 25


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI Query with Limit pages through LastEvaluatedKey to exactly one partition's items,
    ordered by the index sort key, at most Limit per page, reversed by ScanIndexForward=False."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-gsi-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "id", "AttributeType": "S"},
            {"AttributeName": "owner", "AttributeType": "S"},
            {"AttributeName": "rank", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [{"AttributeName": "owner", "KeyType": "HASH"},
                          {"AttributeName": "rank", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, table))
    _wait_active(ddb, table)

    # Items alternate between two owners; ranks are written out of order.
    expected = {"alice": [], "bob": []}
    for i in range(_ITEMS):
        owner = "alice" if i % 2 == 0 else "bob"
        rank = (i * 11) % 97
        item_id = f"item-{i:02d}"
        ddb.put_item(TableName=table, Item={
            "id": {"S": item_id}, "owner": {"S": owner}, "rank": {"N": str(rank)},
            "payload": {"S": f"payload-{i}"},
        })
        expected[owner].append((rank, item_id, f"payload-{i}"))
    for owner in expected:
        expected[owner].sort()

    for owner in ("alice", "bob"):
        want = expected[owner]
        forward = _poll_full(ddb, table, owner, len(want), forward=True)
        assert forward == want, (
            f"GSI Query for {owner} with Limit={_PAGE} collected {forward!r}, expected the "
            f"{len(want)} items in ascending rank {want!r}"
        )
        backward = _collect(ddb, table, owner, forward=False)
        assert backward == list(reversed(want)), (
            f"ScanIndexForward=False for {owner} collected {backward!r}, expected the reverse"
        )

    ddb.delete_table(TableName=table)
    deadline = time.monotonic() + 120
    while True:
        try:
            ddb.describe_table(TableName=table)
        except ClientError as e:
            assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
                f"DescribeTable on the deleted table answered {e.response['Error'].get('Code')!r}"
            )
            assert e.response["Error"]["Message"] == f"Requested resource not found: Table: {table} not found", (
                f"expected AWS's exact ResourceNotFoundException message, got {e.response['Error']['Message']!r}"
            )
            assert 400 <= e.response["ResponseMetadata"]["HTTPStatusCode"] < 500
            break
        assert time.monotonic() < deadline, "the deleted table still describes after 120s"
        time.sleep(3)


def _collect(ddb, table, owner, *, forward):
    """Every item of one GSI partition, following LastEvaluatedKey; each page holds <= Limit."""
    out, start, pages = [], None, 0
    while True:
        kwargs = {
            "TableName": table, "IndexName": _INDEX, "Limit": _PAGE,
            "KeyConditionExpression": "#o = :o",
            "ExpressionAttributeNames": {"#o": "owner"},
            "ExpressionAttributeValues": {":o": {"S": owner}},
            "ScanIndexForward": forward,
        }
        if start is not None:
            kwargs["ExclusiveStartKey"] = start
        page = ddb.query(**kwargs)
        items = page.get("Items", [])
        assert len(items) <= _PAGE, f"a page held {len(items)} items, more than Limit={_PAGE}"
        assert page.get("Count") == len(items), (
            f"page Count {page.get('Count')!r} differs from its {len(items)} items"
        )
        out.extend((int(i["rank"]["N"]), i["id"]["S"], i["payload"]["S"]) for i in items)
        pages += 1
        assert pages <= 20, "LastEvaluatedKey never ran out after 20 pages"
        start = page.get("LastEvaluatedKey")
        if not start:
            return out
        assert set(start) == {"id", "owner", "rank"}, (
            f"a GSI LastEvaluatedKey carries the table and index keys, got {sorted(start)}"
        )


def _poll_full(ddb, table, owner, n, *, forward):
    """GSIs are eventually consistent: collect until the partition holds all n items."""
    deadline = time.monotonic() + 60
    while True:
        got = _collect(ddb, table, owner, forward=forward)
        if len(got) >= n or time.monotonic() >= deadline:
            return got
        time.sleep(2)


def _wait_active(ddb, table, timeout_s=180.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table)["Table"]
        indexes = last.get("GlobalSecondaryIndexes", [])
        if (last["TableStatus"] == "ACTIVE" and indexes
                and all(g.get("IndexStatus") == "ACTIVE" for g in indexes)):
            return
        time.sleep(3)
    raise AssertionError(f"table {table} or its GSI did not become ACTIVE: {last!r}")


def _delete_table_if_exists(ddb, table) -> None:
    try:
        ddb.delete_table(TableName=table)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
