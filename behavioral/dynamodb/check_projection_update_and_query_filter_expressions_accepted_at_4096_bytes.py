"""projection-update-and-query-filter-expressions-accepted-at-4096-bytes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "projection-update-and-query-filter-expressions-accepted-at-4096-bytes"
GROUP = "validation"
SERVICES = ["dynamodb"]

_MAX = 4096


def _path_of_len(total: int) -> str:
    """One attribute-name path of exactly `total` bytes."""
    return "a" + "z" * (total - 1)


def _teardown(undo, *not_found: str, timeout_s: float = 300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo() -> None:
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table: str) -> dict:
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A 4096-byte ProjectionExpression (GetItem), UpdateExpression (UpdateItem) and Query
    FilterExpression are each accepted and applied, not just parsed.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-expr4096-")
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    # --- GetItem ProjectionExpression at exactly 4096 bytes ---
    proj_prefix = "foo, "
    proj_pad = _path_of_len(_MAX - len(proj_prefix))
    projection = proj_prefix + proj_pad
    assert len(projection) == _MAX, f"ProjectionExpression length {len(projection)!r}, expected {_MAX!r}"

    ddb.put_item(TableName=table, Item={
        "pk": {"S": "item"}, "sk": {"S": "projection"},
        "foo": {"S": "kept"}, "bar": {"S": "dropped"}, proj_pad: {"S": "kept-too"},
    })
    got = ddb.get_item(
        TableName=table, Key={"pk": {"S": "item"}, "sk": {"S": "projection"}},
        ProjectionExpression=projection, ConsistentRead=True,
    )["Item"]
    assert got == {"foo": {"S": "kept"}, proj_pad: {"S": "kept-too"}}, (
        f"GetItem with a 4096-byte ProjectionExpression returned {got!r}, expected exactly "
        f"'foo' and the projected long attribute, excluding 'bar'"
    )

    # --- UpdateItem UpdateExpression at exactly 4096 bytes ---
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "item"}, "sk": {"S": "update"}, "foo": {"S": "before"},
    })
    update_prefix = "SET foo = :v, "
    update_suffix = " = :v2"
    update_pad = _path_of_len(_MAX - len(update_prefix) - len(update_suffix))
    update_expr = update_prefix + update_pad + update_suffix
    assert len(update_expr) == _MAX, f"UpdateExpression length {len(update_expr)!r}, expected {_MAX!r}"

    ddb.update_item(
        TableName=table, Key={"pk": {"S": "item"}, "sk": {"S": "update"}},
        UpdateExpression=update_expr,
        ExpressionAttributeValues={":v": {"S": "after"}, ":v2": {"S": "added"}},
    )
    got = ddb.get_item(
        TableName=table, Key={"pk": {"S": "item"}, "sk": {"S": "update"}}, ConsistentRead=True,
    )["Item"]
    assert got == {
        "pk": {"S": "item"}, "sk": {"S": "update"}, "foo": {"S": "after"}, update_pad: {"S": "added"},
    }, f"after a 4096-byte UpdateExpression the item read back {got!r}"

    # --- Query FilterExpression at exactly 4096 bytes ---
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "query"}, "sk": {"S": "k1"}, "flag": {"S": "match"},
    })
    ddb.put_item(TableName=table, Item={
        "pk": {"S": "query"}, "sk": {"S": "k2"}, "flag": {"S": "other"},
    })
    filter_prefix = "flag = :v AND attribute_not_exists("
    filter_suffix = ")"
    filter_pad = _path_of_len(_MAX - len(filter_prefix) - len(filter_suffix))
    filter_expr = filter_prefix + filter_pad + filter_suffix
    assert len(filter_expr) == _MAX, f"FilterExpression length {len(filter_expr)!r}, expected {_MAX!r}"

    page = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p", FilterExpression=filter_expr,
        ExpressionAttributeValues={":p": {"S": "query"}, ":v": {"S": "match"}},
        ConsistentRead=True,
    )
    assert (page["Count"], page["ScannedCount"]) == (1, 2), (
        f"Query with a 4096-byte FilterExpression gave Count {page['Count']!r}, "
        f"ScannedCount {page['ScannedCount']!r}, expected 1 of 2 scanned"
    )
    assert page["Items"] == [{"pk": {"S": "query"}, "sk": {"S": "k1"}, "flag": {"S": "match"}}], (
        f"Query with a 4096-byte FilterExpression returned {page['Items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
