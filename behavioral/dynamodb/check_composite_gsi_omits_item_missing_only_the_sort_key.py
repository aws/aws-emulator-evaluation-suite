"""composite-gsi-omits-item-missing-only-the-sort-key."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "composite-gsi-omits-item-missing-only-the-sort-key"
GROUP = "gsi"
SERVICES = ["dynamodb"]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An item carrying a composite GSI's partition key but not its sort key is excluded from
    that GSI: a Query and a Scan on the index both omit it, while a base-table Scan holds it.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
            {"AttributeName": "gsk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "gsi-1",
            "KeySchema": [
                {"AttributeName": "gpk", "KeyType": "HASH"},
                {"AttributeName": "gsk", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Carries the GSI partition key but not its sort key: must never appear in the index.
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "no-sort"}, "sk": {"S": "1"}, "gpk": {"S": "group-A"},
    })
    # Written afterwards with both GSI key attributes: its arrival in the index is the later
    # positive control that proves the earlier write has had time to propagate.
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "full"}, "sk": {"S": "1"}, "gpk": {"S": "group-A"}, "gsk": {"S": "a"},
    })

    base = ddb.scan(TableName=table, ConsistentRead=True)
    base_pks = {item["pk"]["S"] for item in base["Items"]}
    assert base_pks == {"full", "no-sort"}, (
        f"the base table must hold both items regardless of the GSI, got {sorted(base_pks)!r}"
    )

    def _probe():
        q = ddb.query(TableName=table, IndexName="gsi-1", KeyConditionExpression="gpk = :g",
                      ExpressionAttributeValues={":g": {"S": "group-A"}})
        s = ddb.scan(TableName=table, IndexName="gsi-1")
        return q, s

    resp_q, resp_s = _poll_until(
        probe=_probe,
        predicate=lambda qs: qs[0]["Count"] == 1 and qs[1]["Count"] == 1,
        description="gsi-1 propagation",
    )

    q_pks = {item["pk"]["S"] for item in resp_q["Items"]}
    assert q_pks == {"full"}, (
        f"a Query on gpk=group-A must return only the fully-keyed item, got {sorted(q_pks)!r}"
    )

    # The Scan is the real proof: it enumerates the index's own contents, so an index that
    # materialized "no-sort" under some other sort-key value cannot hide behind a targeted Query.
    s_pks = {item["pk"]["S"] for item in resp_s["Items"]}
    assert s_pks == {"full"}, (
        f"a Scan of gsi-1 must contain only the fully-keyed item, got {sorted(s_pks)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
