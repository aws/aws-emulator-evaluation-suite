"""gsi-scan-all-projection-and-filtered-limit-paging."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "gsi-scan-all-projection-and-filtered-limit-paging"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_IDX = "gsi-all"

#: pk, gpk (GSI hash key), category, body.
_ITEMS = tuple(
    {
        "pk": {"S": f"p{i}"},
        "sk": {"S": "fixed"},
        "gpk": {"S": f"g{i}"},
        "category": {"S": "even" if i % 2 == 0 else "odd"},
        "body": {"S": f"body{i}"},
    }
    for i in range(7)
)
_EVEN_PKS = tuple(sorted(it["pk"]["S"] for it in _ITEMS if it["category"]["S"] == "even"))


def _poll(fn, pred, *, timeout_s, interval_s=2.0, description="condition"):
    """Poll `fn` until `pred` holds: a GSI is eventually consistent, so this waits rather than
    sleeping a fixed amount."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {value!r}")
        time.sleep(interval_s)
        value = fn()
    return value


def _scan_all_pages(ddb, **kwargs) -> list:
    """Every item of a Scan, following LastEvaluatedKey."""
    items, start, guard = [], None, 0
    while True:
        kw = dict(kwargs)
        if start:
            kw["ExclusiveStartKey"] = start
        page = ddb.scan(**kw)
        items.extend(page.get("Items", []))
        start = page.get("LastEvaluatedKey")
        guard += 1
        assert guard < 50, "scan paging did not terminate"
        if not start:
            return items


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A Scan of an ALL-projection GSI returns every item attribute, and a FilterExpression with
    Limit paging over that GSI returns exactly the matching rows across pages.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-gsiscan-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {"IndexName": _IDX, "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}],
             "Projection": {"ProjectionType": "ALL"}},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for item in _ITEMS:
        ddb.put_item(TableName=table, Item=item)

    # --- ALL projection: the GSI serves every attribute of the base item, once it has caught up ---
    all_items = _poll(
        lambda: ddb.scan(TableName=table, IndexName=_IDX)["Items"],
        lambda items: len(items) == len(_ITEMS),
        timeout_s=120, description=f"all {len(_ITEMS)} items propagating into {_IDX}",
    )
    by_pk = {it["pk"]["S"]: it for it in all_items}
    for want in _ITEMS:
        got = by_pk.get(want["pk"]["S"])
        assert got == want, f"ALL GSI item for {want['pk']['S']!r} is {got!r}, expected {want!r}"

    # --- FilterExpression + Limit paging on the GSI returns exactly the matching rows ---
    filtered = _scan_all_pages(
        ddb, TableName=table, IndexName=_IDX, Limit=2,
        FilterExpression="category = :c", ExpressionAttributeValues={":c": {"S": "even"}},
    )
    got_pks = tuple(sorted(it["pk"]["S"] for it in filtered))
    assert got_pks == _EVEN_PKS, (
        f"filtered+paginated GSI scan returned pks {got_pks!r}, expected {_EVEN_PKS!r}"
    )
    for it in filtered:
        assert it["category"] == {"S": "even"}, f"a non-matching item leaked through the filter: {it!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
