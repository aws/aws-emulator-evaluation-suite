"""keys-only-gsi-string-sort-key-pages-in-byte-order."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "keys-only-gsi-string-sort-key-pages-in-byte-order"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INDEX = "by-group-label"
_PAGE = 3
#: Sort-key strings whose byte order differs from numeric and case-folded order.
_LABELS = ["10", "9", "B", "a", "é", "a b", "Z", "~", "A", "a\u0301"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A KEYS_ONLY GSI with a numeric partition and string sort key pages by Limit=3 through
    LastEvaluatedKey to exactly one group's indexed items, in UTF-8 byte order of the sort key,
    each carrying only the table and index keys; items without the sort key are never indexed.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-gsi-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "id", "AttributeType": "S"},
            {"AttributeName": "grp", "AttributeType": "N"},
            {"AttributeName": "label", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [{"AttributeName": "grp", "KeyType": "HASH"},
                          {"AttributeName": "label", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "KEYS_ONLY"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, table))
    _wait_active(ddb, table)

    expected = {"7": [], "-1": []}
    for i, label in enumerate(_LABELS):
        for grp in ("7", "-1"):
            item_id = f"{grp}/{i:02d}"
            item = {"id": {"S": item_id}, "grp": {"N": grp}, "label": {"S": label},
                    "payload": {"S": f"p{i}"}}
            expected[grp].append((label.encode("utf-8"), item_id, label))
            ddb.put_item(TableName=table, Item=item)
        # A sparse item: it has the partition attribute but no sort key, so it is not indexed.
        ddb.put_item(TableName=table, Item={"id": {"S": f"sparse-{i}"}, "grp": {"N": "7"}})
    want = {g: [(item_id, label) for _, item_id, label in sorted(rows)] for g, rows in expected.items()}

    for grp in ("7", "-1"):
        forward = _poll_full(ddb, table, grp, len(want[grp]), forward=True)
        assert forward == want[grp], (
            f"KEYS_ONLY GSI Query for grp={grp} with Limit={_PAGE} collected {forward!r}, expected "
            f"{want[grp]!r} in byte order of the label"
        )
        backward = _collect(ddb, table, grp, forward=False)
        assert backward == list(reversed(want[grp])), (
            f"ScanIndexForward=False for grp={grp} collected {backward!r}, expected the reverse"
        )


def _collect(ddb, table, grp, *, forward):
    """Every (id, label) of one GSI partition, following LastEvaluatedKey; each page holds <= Limit
    items with exactly the key attributes.
    """
    out, start, pages = [], None, 0
    while True:
        kwargs = {
            "TableName": table, "IndexName": _INDEX, "Limit": _PAGE,
            "KeyConditionExpression": "grp = :g",
            "ExpressionAttributeValues": {":g": {"N": grp}},
            "ScanIndexForward": forward,
        }
        if start is not None:
            kwargs["ExclusiveStartKey"] = start
        page = ddb.query(**kwargs)
        items = page["Items"]
        assert len(items) <= _PAGE, f"a page held {len(items)} items, more than Limit={_PAGE}"
        assert page["Count"] == len(items), f"page Count {page['Count']!r} differs from its {len(items)} items"
        for i in items:
            assert set(i) == {"id", "grp", "label"}, f"a KEYS_ONLY index item carried {sorted(i)}"
            assert i["grp"] == {"N": grp}, f"an item of another partition came back: {i!r}"
        out.extend((i["id"]["S"], i["label"]["S"]) for i in items)
        pages += 1
        assert pages <= 20, "LastEvaluatedKey never ran out after 20 pages"
        start = page.get("LastEvaluatedKey")
        if not start:
            return out
        assert set(start) == {"id", "grp", "label"}, (
            f"a GSI LastEvaluatedKey carries the table and index keys, got {sorted(start)}"
        )


def _poll_full(ddb, table, grp, n, *, forward):
    """GSIs are eventually consistent: collect until the partition holds all n items."""
    deadline = time.monotonic() + 40
    while True:
        got = _collect(ddb, table, grp, forward=forward)
        if len(got) >= n or time.monotonic() >= deadline:
            return got
        time.sleep(2)


def _wait_active(ddb, table, timeout_s=40.0) -> None:
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
