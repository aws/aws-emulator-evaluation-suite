"""gsi-query-filter-on-its-own-aliased-key-attribute-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-query-filter-on-its-own-aliased-key-attribute-rejected"
GROUP = "access_path"
SERVICES = ["dynamodb"]
_GSI = "gsi1"
_GH = "shared"
_VISIBLE_S = 180
_KEY_IN_FILTER = (
    "ValidationException",
    "Filter Expression can only contain non-primary key attributes: Primary key attribute: gh",
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
    """A GSI Query's FilterExpression naming the index's own hash key through an
    ExpressionAttributeNames alias is refused with a message naming the resolved attribute,
    and the table is unchanged; an aliased filter on a non-key attribute still narrows.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbgsi-aliasedkey-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gh", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": _GSI,
            "KeySchema": [{"AttributeName": "gh", "KeyType": "HASH"}],
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
        "pk": {"S": "p1"}, "sk": {"S": "s1"}, "gh": {"S": _GH}, "note": {"S": "alpha"},
    })
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "p2"}, "sk": {"S": "s2"}, "gh": {"S": _GH}, "note": {"S": "beta"},
    })

    # GSIs are eventually consistent: wait for both items before trusting the control below.
    deadline = time.monotonic() + _VISIBLE_S
    unfiltered = {"Count": 0}
    while True:
        unfiltered = ddb.query(TableName=table, IndexName=_GSI, KeyConditionExpression="gh = :g",
                               ExpressionAttributeValues={":g": {"S": _GH}})
        if unfiltered["Count"] == 2 or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert unfiltered["Count"] == 2, (
        f"expected both seeded items visible on {_GSI} within {_VISIBLE_S}s, got Count={unfiltered['Count']}"
    )

    # Positive control: the alias mechanism itself narrows correctly on a non-key attribute.
    control = ddb.query(TableName=table, IndexName=_GSI, KeyConditionExpression="gh = :g",
                        FilterExpression="#n = :want",
                        ExpressionAttributeNames={"#n": "note"},
                        ExpressionAttributeValues={":g": {"S": _GH}, ":want": {"S": "alpha"}})
    assert [i["note"]["S"] for i in control["Items"]] == ["alpha"], (
        f"aliased filter on the non-key attribute returned {control['Items']!r}, "
        f"expected only the item whose note is 'alpha'"
    )

    # Break exactly one thing: the filter names the queried index's own hash key, but through
    # an alias instead of the bare attribute name.
    expect_error(lambda: ddb.query(
        TableName=table, IndexName=_GSI, KeyConditionExpression="gh = :g",
        FilterExpression="#g2 = :g2",
        ExpressionAttributeNames={"#g2": "gh"},
        ExpressionAttributeValues={":g": {"S": _GH}, ":g2": {"S": _GH}},
    ), *_KEY_IN_FILTER)

    # The rejected call wrote or deleted nothing: the base table still holds only the seed.
    final = ddb.scan(TableName=table, ConsistentRead=True)["Items"]
    assert sorted(i["pk"]["S"] for i in final) == ["p1", "p2"], (
        f"expected only the two seeded items to remain, got {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
