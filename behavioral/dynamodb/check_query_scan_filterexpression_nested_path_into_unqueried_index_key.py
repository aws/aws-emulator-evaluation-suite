"""query-scan-filterexpression-nested-path-into-unqueried-index-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-scan-filterexpression-nested-path-into-unqueried-index-key"
GROUP = "key_attribute_filter_expression"
SERVICES = ["dynamodb"]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


_INDEX_KEY_IN_SCOPE_REJECTED = (
    "ValidationException",
    "Filter Expression can only contain non-primary key attributes: Primary key attribute: gr",
)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FilterExpression nested path into a secondary index's key attribute is refused only
    when that index is the one being queried, even for the index's other key; the same
    attribute is an ordinary attribute on a Scan or on a Query of the base table.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-idxfilt-")

    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gh", "AttributeType": "S"},
            {"AttributeName": "gr", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "gsi1",
                "KeySchema": [
                    {"AttributeName": "gh", "KeyType": "HASH"},
                    {"AttributeName": "gr", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    deadline = time.monotonic() + 120
    while True:
        gsis = ddb.describe_table(TableName=table)["Table"].get("GlobalSecondaryIndexes", [])
        if gsis and gsis[0]["IndexStatus"] == "ACTIVE":
            break
        assert time.monotonic() < deadline, f"gsi1 did not reach ACTIVE, last saw {gsis!r}"
        time.sleep(2)

    ddb.put_item(
        TableName=table,
        Item={
            "pk": {"S": "p"},
            "sk": {"S": "s1"},
            "gh": {"S": "g"},
            "gr": {"S": "r1"},
            "color": {"S": "red"},
        },
    )

    # A Scan has no key condition at all: a nested path into a secondary index's key
    # attribute is an ordinary document-path lookup, not a protected key reference.
    scan_nested = ddb.scan(
        TableName=table,
        FilterExpression="gh.x = :v",
        ExpressionAttributeValues={":v": {"S": "z"}},
        ConsistentRead=True,
    )
    assert scan_nested["Count"] == 0, (
        f"Scan FilterExpression nested into the GSI hash key must not error; it matches by "
        f"document path, which is absent, so Count should be 0, got {scan_nested['Count']}"
    )
    assert scan_nested["ScannedCount"] == 1, (
        f"Scan must still have scanned the one seeded item, got ScannedCount "
        f"{scan_nested['ScannedCount']}"
    )

    scan_control = ddb.scan(
        TableName=table,
        FilterExpression="color = :c",
        ExpressionAttributeValues={":c": {"S": "red"}},
        ConsistentRead=True,
    )
    assert scan_control["Count"] == 1, f"Scan positive control matched {scan_control['Count']}, expected 1"
    assert scan_control["Items"][0]["pk"] == {"S": "p"}, (
        f"Scan positive control returned {scan_control['Items'][0]!r}, expected the seeded item"
    )

    # A base-table Query names no index: the GSI's key attribute is likewise an ordinary
    # attribute there, even though the same attribute is protected while querying that index.
    base_query_nested = ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :p",
        FilterExpression="gh.x = :v",
        ExpressionAttributeValues={":p": {"S": "p"}, ":v": {"S": "z"}},
        ConsistentRead=True,
    )
    assert base_query_nested["Count"] == 0, (
        f"base-table Query FilterExpression nested into the GSI hash key must not error; "
        f"got Count {base_query_nested['Count']}"
    )

    base_query_control = ddb.query(
        TableName=table,
        KeyConditionExpression="pk = :p",
        FilterExpression="color = :c",
        ExpressionAttributeValues={":p": {"S": "p"}, ":c": {"S": "red"}},
        ConsistentRead=True,
    )
    assert base_query_control["Count"] == 1, (
        f"base-table Query positive control matched {base_query_control['Count']}, expected 1"
    )
    assert base_query_control["Items"][0]["sk"] == {"S": "s1"}, (
        f"base-table Query positive control returned {base_query_control['Items'][0]!r}, "
        f"expected the seeded item"
    )

    # Querying gsi1 itself protects BOTH of its key attributes, not only the one named in
    # KeyConditionExpression: a nested path into the index's other key is still refused.
    deadline = time.monotonic() + 60
    while True:
        index_control = ddb.query(
            TableName=table,
            IndexName="gsi1",
            KeyConditionExpression="gh = :g",
            FilterExpression="color = :c",
            ExpressionAttributeValues={":g": {"S": "g"}, ":c": {"S": "red"}},
        )
        if index_control["Count"] == 1:
            break
        assert time.monotonic() < deadline, (
            f"item never became visible on gsi1, last saw Count {index_control['Count']}"
        )
        time.sleep(2)
    assert index_control["Items"][0]["gr"] == {"S": "r1"}, (
        f"index Query positive control returned {index_control['Items'][0]!r}, "
        f"expected the seeded item"
    )

    expect_error(
        lambda: ddb.query(
            TableName=table,
            IndexName="gsi1",
            KeyConditionExpression="gh = :g",
            FilterExpression="gr.x = :v",
            ExpressionAttributeValues={":g": {"S": "g"}, ":v": {"S": "z"}},
        ),
        *_INDEX_KEY_IN_SCOPE_REJECTED,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
