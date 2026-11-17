"""query-gsi-and-lsi-filter-on-base-table-sort-key-accepted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-gsi-and-lsi-filter-on-base-table-sort-key-accepted"
GROUP = "access_path"
SERVICES = ["dynamodb"]
_GSI = "gsi1"
_LSI = "lsi1"
_VISIBLE_S = 180
_GSI_KEY_IN_FILTER = (
    "ValidationException",
    "Filter Expression can only contain non-primary key attributes: Primary key attribute: gh",
)
_LSI_KEY_IN_FILTER = (
    "ValidationException",
    "Filter Expression can only contain non-primary key attributes: Primary key attribute: lsk",
)


def expect_error(fn, code: str, message: str) -> None:
    """``fn()`` is refused with exactly (``code``, ``message``); an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert (err.get("Code"), err.get("Message")) == (code, message), (
            f"expected {code}: {message!r}, got {err.get('Code')}: {err.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Query against a GSI or an LSI accepts a FilterExpression on the base table's own sort
    key, not a key of either index, and filters the page by it; naming the queried index's own
    key attribute in the filter is refused with the exact message.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-basekeyfilt-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gh", "AttributeType": "S"},
            {"AttributeName": "lsk", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": _GSI,
                "KeySchema": [{"AttributeName": "gh", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        LocalSecondaryIndexes=[
            {
                "IndexName": _LSI,
                "KeySchema": [
                    {"AttributeName": "pk", "KeyType": "HASH"},
                    {"AttributeName": "lsk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    deadline = time.monotonic() + _VISIBLE_S
    while True:
        gsis = ddb.describe_table(TableName=table)["Table"].get("GlobalSecondaryIndexes", [])
        if gsis and gsis[0]["IndexStatus"] == "ACTIVE":
            break
        assert time.monotonic() < deadline, f"{_GSI} did not reach ACTIVE, last saw {gsis!r}"
        time.sleep(2)

    ddb.put_item(TableName=table, Item={
        "pk": {"S": "p1"}, "sk": {"S": "keep"}, "gh": {"S": "g"}, "lsk": {"S": "l1"},
    })
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "p1"}, "sk": {"S": "skip"}, "gh": {"S": "g"}, "lsk": {"S": "l2"},
    })

    # GSI arm: wait for both items to propagate, then prove a filter on the base table's sort
    # key -- not a key of gsi1 -- actually selects between them, not merely passes through.
    deadline = time.monotonic() + _VISIBLE_S
    unfiltered = {"Count": 0}
    while True:
        unfiltered = ddb.query(TableName=table, IndexName=_GSI, KeyConditionExpression="gh = :g",
                               ExpressionAttributeValues={":g": {"S": "g"}})
        if unfiltered["Count"] == 2 or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert unfiltered["Count"] == 2, (
        f"expected both seeded items visible on {_GSI} within {_VISIBLE_S}s, got Count={unfiltered['Count']}"
    )

    gsi_filtered = ddb.query(TableName=table, IndexName=_GSI, KeyConditionExpression="gh = :g",
                             FilterExpression="sk = :keep",
                             ExpressionAttributeValues={":g": {"S": "g"}, ":keep": {"S": "keep"}})
    assert [i["sk"] for i in gsi_filtered["Items"]] == [{"S": "keep"}], (
        f"GSI Query filtered on the base table's sort key returned {gsi_filtered['Items']!r}, "
        f"expected only the item whose sk is 'keep'"
    )

    # LSI arm: the same base-table sort-key filter, strongly consistent -- no propagation wait.
    lsi_filtered = ddb.query(TableName=table, IndexName=_LSI, ConsistentRead=True,
                             KeyConditionExpression="pk = :p", FilterExpression="sk = :keep",
                             ExpressionAttributeValues={":p": {"S": "p1"}, ":keep": {"S": "keep"}})
    assert [i["sk"] for i in lsi_filtered["Items"]] == [{"S": "keep"}], (
        f"LSI Query filtered on the base table's sort key returned {lsi_filtered['Items']!r}, "
        f"expected only the item whose sk is 'keep'"
    )

    # Break exactly one thing: name the queried index's own key attribute in the filter instead.
    expect_error(lambda: ddb.query(
        TableName=table, IndexName=_GSI, KeyConditionExpression="gh = :g",
        FilterExpression="gh = :g2",
        ExpressionAttributeValues={":g": {"S": "g"}, ":g2": {"S": "g"}},
    ), *_GSI_KEY_IN_FILTER)
    expect_error(lambda: ddb.query(
        TableName=table, IndexName=_LSI, ConsistentRead=True,
        KeyConditionExpression="pk = :p", FilterExpression="lsk = :l",
        ExpressionAttributeValues={":p": {"S": "p1"}, ":l": {"S": "l1"}},
    ), *_LSI_KEY_IN_FILTER)

    # Neither rejected call wrote or deleted anything: the base table still holds only the seed.
    final = ddb.scan(TableName=table, ConsistentRead=True)["Items"]
    assert sorted(i["sk"]["S"] for i in final) == ["keep", "skip"], (
        f"expected only the two seeded items to remain, got {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
