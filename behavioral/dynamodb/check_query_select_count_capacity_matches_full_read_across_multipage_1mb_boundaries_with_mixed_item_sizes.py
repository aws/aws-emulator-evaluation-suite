"""query-select-count-capacity-matches-full-read-across-multipage-1mb-boundaries-with-mixed-item-sizes."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-select-count-capacity-matches-full-read-across-multipage-1mb-boundaries-with-mixed-item-sizes"
GROUP = "capacity"
SERVICES = ["dynamodb"]

_ONE_MB = 1024 * 1024
_MAX_PAGES = 12
# Ascending sizes so the later items in the partition are larger than the earlier ones.
_PAYLOADS = [100_000, 200_000, 300_000, 390_000, 390_000, 390_000, 390_000, 390_000]
_SENTINEL_SK = f"{len(_PAYLOADS):03d}"


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


def _walk(ddb, table, pk, *, select=None):
    """Every page of a Query over partition key pk, following LastEvaluatedKey."""
    pages = []
    kwargs = {
        "TableName": table,
        "KeyConditionExpression": "pk = :p",
        "ExpressionAttributeValues": {":p": {"S": pk}},
        "ConsistentRead": True,
        "ReturnConsumedCapacity": "TOTAL",
    }
    if select:
        kwargs["Select"] = select
    while True:
        resp = ddb.query(**kwargs)
        pages.append(resp)
        if "LastEvaluatedKey" not in resp:
            return pages
        assert len(pages) < _MAX_PAGES, f"Query did not end after {_MAX_PAGES} pages"
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query with Select=COUNT over a partition of unevenly sized items pages at the same 1 MB
    boundaries as a full read, with matching Count, ScannedCount and ConsumedCapacity per page.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddb-qmix-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=t), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for i, size in enumerate(_PAYLOADS):
        ddb.put_item(TableName=t, Item={
            "pk": {"S": "big"}, "sk": {"S": f"{i:03d}"}, "payload": {"S": "x" * size},
        })
    # A sentinel item past the last real one makes "more data remains" unambiguous on the final
    # page too: without it, AWS inconsistently reports LastEvaluatedKey when the 1 MB limit is
    # reached exactly on the partition's last item.
    ddb.put_item(TableName=t, Item={"pk": {"S": "big"}, "sk": {"S": _SENTINEL_SK}, "payload": {"S": "y"}})
    assert sum(_PAYLOADS) > 2 * _ONE_MB, (
        "the partition must exceed 2 MB so at least two pages truncate before the last page"
    )

    baseline = _walk(ddb, t, "big")
    assert len(baseline) >= 3, (
        f"a partition of ascending item sizes above 2 MB must span at least 3 pages, got "
        f"{len(baseline)}"
    )
    for n, page in enumerate(baseline, 1):
        assert page["Count"] == page["ScannedCount"] == len(page["Items"]), (
            f"baseline page {n}: Count {page['Count']!r} ScannedCount {page['ScannedCount']!r} "
            f"for {len(page['Items'])} items"
        )
    assert "LastEvaluatedKey" not in baseline[-1], (
        f"the last baseline page must reach the end of the partition, got "
        f"{baseline[-1].get('LastEvaluatedKey')!r}"
    )
    for page in baseline[:-1]:
        assert "LastEvaluatedKey" in page, "every page but the last must carry a LastEvaluatedKey"
    seen = sorted(it["sk"]["S"] for page in baseline for it in page["Items"])
    assert seen == [f"{i:03d}" for i in range(len(_PAYLOADS))] + [_SENTINEL_SK], (
        f"baseline pages returned {seen!r}, expected every item plus the sentinel exactly once"
    )

    counted = _walk(ddb, t, "big", select="COUNT")
    assert len(counted) == len(baseline), (
        f"Select=COUNT must page at the same boundaries: {len(counted)} pages vs the full read's "
        f"{len(baseline)}"
    )
    for n, (c, b) in enumerate(zip(counted, baseline), 1):
        assert not c.get("Items"), f"Select=COUNT page {n} must return no Items, got {c.get('Items')!r}"
        assert c["Count"] == b["Count"], (
            f"Select=COUNT page {n} Count {c['Count']!r} must equal the full read's {b['Count']!r}"
        )
        assert c["ScannedCount"] == b["ScannedCount"], (
            f"Select=COUNT page {n} ScannedCount {c['ScannedCount']!r} must equal the full read's "
            f"{b['ScannedCount']!r}"
        )
        assert c.get("LastEvaluatedKey") == b.get("LastEvaluatedKey"), (
            f"Select=COUNT page {n} LastEvaluatedKey {c.get('LastEvaluatedKey')!r} must equal the "
            f"full read's {b.get('LastEvaluatedKey')!r}"
        )
        assert c["ConsumedCapacity"]["CapacityUnits"] == b["ConsumedCapacity"]["CapacityUnits"], (
            f"Select=COUNT page {n} billed {c['ConsumedCapacity']['CapacityUnits']!r} "
            f"CapacityUnits, the full read billed {b['ConsumedCapacity']['CapacityUnits']!r} -- "
            f"unevenly sized items must still price identically by Select"
        )

    total_rcu = sum(p["ConsumedCapacity"]["CapacityUnits"] for p in counted)
    assert total_rcu == sum(p["ConsumedCapacity"]["CapacityUnits"] for p in baseline), (
        "the total capacity billed across all Select=COUNT pages must equal the full read's total"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
