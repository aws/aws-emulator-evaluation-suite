"""update-item-gsi-partition-key-value-over-2048-bytes-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-gsi-partition-key-value-over-2048-bytes-rejected"
GROUP = "limits"
SERVICES = ["dynamodb"]

_OVER_LIMIT = (
    "ValidationException",
    "One or more parameter values were invalid: Size limit exceeded for Index Key gpk "
    "Actual Size: 2049 bytes Max Size: 2048 bytes IndexName: gsi1",
)


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; the resource's own not-found
    code means it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_active(ddb, table: str, deadline: float) -> None:
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE with its GSI before the deadline: {desc!r}")


def _code_and_message(fn):
    """The botocore (code, message) *fn* raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


def _poll_query(query, pred, deadline: float):
    result = query()
    while not pred(result) and time.monotonic() < deadline:
        time.sleep(2)
        result = query()
    return result


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem refuses to create a new item whose GSI partition-key attribute is over
    2048 bytes, leaving no item in the base table, while exactly 2048 bytes is accepted and
    queryable on the index.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Limits.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbgks-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "gsi1",
            "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "KEYS_ONLY"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 600.0) - 60.0)
    _wait_active(ddb, table, deadline)

    code, message = _code_and_message(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "over"}},
        UpdateExpression="SET gpk = :g", ExpressionAttributeValues={":g": {"S": "g" * 2049}},
    ))
    assert (code, message) == _OVER_LIMIT, (
        f"a 2049-byte GSI partition-key value was refused as {(code, message)!r}, expected {_OVER_LIMIT!r}"
    )
    assert "Item" not in ddb.get_item(TableName=table, Key={"pk": {"S": "over"}}, ConsistentRead=True), (
        "a new item refused for its GSI key's size must not be created in the base table"
    )

    ok_value = "g" * 2048
    ddb.update_item(
        TableName=table, Key={"pk": {"S": "ok"}},
        UpdateExpression="SET gpk = :g", ExpressionAttributeValues={":g": {"S": ok_value}},
    )
    found = _poll_query(
        lambda: ddb.query(TableName=table, IndexName="gsi1", KeyConditionExpression="gpk = :g",
                          ExpressionAttributeValues={":g": {"S": ok_value}}),
        lambda r: r["Count"] == 1, deadline,
    )
    assert found["Count"] == 1, f"a 2048-byte GSI partition-key value never appeared on gsi1: {found!r}"
    assert found["Items"][0]["pk"] == {"S": "ok"}, f"gsi1 returned the wrong item: {found['Items'][0]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
