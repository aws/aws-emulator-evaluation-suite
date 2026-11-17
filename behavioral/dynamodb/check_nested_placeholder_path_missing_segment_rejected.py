"""nested-placeholder-path-missing-segment-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nested-placeholder-path-missing-segment-rejected"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]

_INVALID_PATH = (
    "ValidationException",
    "The document path provided in the update expression is invalid for update",
)


def expect_error(fn, code: str, message: str) -> None:
    """Assert `fn()` raises a ClientError with exactly `(code, message)`; raises on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err["Code"], err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ADD and DELETE through a per-segment placeholder path are rejected when an
    intermediate segment is absent from the stored item, and the item stays unchanged.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "x"}}
    original = {**key, "fis": {"M": {"isa": {"M": {"events": {"N": "0"}}}}}}
    ddb.put_item(TableName=table, Item=original)

    expect_error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD #f.#x.#e :one",
        ExpressionAttributeNames={"#f": "fis", "#x": "tags", "#e": "events"},
        ExpressionAttributeValues={":one": {"N": "1"}},
    ), *_INVALID_PATH)
    after_add = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_add == original, f"the rejected ADD must leave the item unchanged, got {after_add!r}"

    expect_error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE #f.#y.#l :s",
        ExpressionAttributeNames={"#f": "fis", "#y": "tags", "#l": "labels"},
        ExpressionAttributeValues={":s": {"SS": ["a"]}},
    ), *_INVALID_PATH)
    after_delete = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_delete == original, f"the rejected DELETE must leave the item unchanged, got {after_delete!r}"

    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD #f.#i.#e :one",
        ExpressionAttributeNames={"#f": "fis", "#i": "isa", "#e": "events"},
        ExpressionAttributeValues={":one": {"N": "1"}},
    )
    controlled = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert controlled["fis"]["M"]["isa"]["M"]["events"] == {"N": "1"}, (
        f"the positive-control ADD on an existing segment must apply, got {controlled!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
