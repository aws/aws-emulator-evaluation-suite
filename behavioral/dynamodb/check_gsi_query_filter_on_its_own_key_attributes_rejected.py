"""gsi-query-filter-on-its-own-key-attributes-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-query-filter-on-its-own-key-attributes-rejected"
GROUP = "access_path"
SERVICES = ["dynamodb"]
_GSI = "gsi1"
_VISIBLE_S = 180
_HASH_KEY_IN_FILTER = (
    "ValidationException",
    "Filter Expression can only contain non-primary key attributes: Primary key attribute: gpk",
)
_RANGE_KEY_IN_FILTER = (
    "ValidationException",
    "Filter Expression can only contain non-primary key attributes: Primary key attribute: gsk",
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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI Query's FilterExpression naming the index's own hash or range key attribute is
    refused with the exact message, while a filter on the base table's sort key still matches.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbgsi-ownkey-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
            {"AttributeName": "gsk", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": _GSI,
            "KeySchema": [
                {"AttributeName": "gpk", "KeyType": "HASH"},
                {"AttributeName": "gsk", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
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
        "pk": {"S": "p1"}, "sk": {"S": "keep"}, "gpk": {"S": "g1"}, "gsk": {"S": "k1"},
    })
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "p1"}, "sk": {"S": "skip"}, "gpk": {"S": "g1"}, "gsk": {"S": "k2"},
    })

    # Positive control: a filter on the base table's sort key -- not a key of this index --
    # is accepted and selects between the two seeded items, once both have propagated.
    deadline = time.monotonic() + _VISIBLE_S
    control = {"Count": 0}
    while True:
        control = ddb.query(TableName=table, IndexName=_GSI, KeyConditionExpression="gpk = :g",
                            ExpressionAttributeValues={":g": {"S": "g1"}})
        if control["Count"] == 2 or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert control["Count"] == 2, (
        f"expected both seeded items visible on {_GSI} within {_VISIBLE_S}s, got Count={control['Count']}"
    )
    filtered = ddb.query(TableName=table, IndexName=_GSI, KeyConditionExpression="gpk = :g",
                         FilterExpression="sk = :keep",
                         ExpressionAttributeValues={":g": {"S": "g1"}, ":keep": {"S": "keep"}})
    assert [i["sk"]["S"] for i in filtered["Items"]] == ["keep"], (
        f"filtering on the base table's sort key returned {filtered['Items']!r}, expected only "
        f"the item whose sk is 'keep'"
    )

    # Break exactly one thing: the filter names the queried index's own hash key.
    expect_error(lambda: ddb.query(
        TableName=table, IndexName=_GSI, KeyConditionExpression="gpk = :g",
        FilterExpression="gpk = :g2",
        ExpressionAttributeValues={":g": {"S": "g1"}, ":g2": {"S": "g1"}},
    ), *_HASH_KEY_IN_FILTER)

    # Break exactly one thing: the filter names the queried index's own range key.
    expect_error(lambda: ddb.query(
        TableName=table, IndexName=_GSI, KeyConditionExpression="gpk = :g",
        FilterExpression="gsk = :k",
        ExpressionAttributeValues={":g": {"S": "g1"}, ":k": {"S": "k1"}},
    ), *_RANGE_KEY_IN_FILTER)

    # Neither rejected call wrote or deleted anything: the base table still holds only the seed.
    final = ddb.scan(TableName=table, ConsistentRead=True)["Items"]
    assert sorted(i["sk"]["S"] for i in final) == ["keep", "skip"], (
        f"expected only the two seeded items to remain, got {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
