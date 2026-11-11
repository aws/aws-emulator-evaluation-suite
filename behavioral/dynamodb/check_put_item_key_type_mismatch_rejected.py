"""put-item-key-type-mismatch-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-item-key-type-mismatch-rejected"
GROUP = "representation"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem with a partition key value whose AttributeValue type (N) does not match
    the table's declared key type (S) is rejected with ValidationException, the item is
    never persisted, and a same-shaped correctly-typed PutItem succeeds."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx)

    bad_pk_numeric = 424242
    err = _error(
        lambda: ddb.put_item(
            TableName=table, Item={"pk": {"N": str(bad_pk_numeric)}, "note": {"S": "bad"}}
        )
    )
    assert err.get("Code") == "ValidationException", (
        f"expected ValidationException, got {err.get('Code')!r}"
    )
    expected = "One or more parameter values were invalid: Type mismatch for key pk expected: S actual: N"
    assert err.get("Message") == expected, (
        f"expected message {expected!r}, got {err.get('Message')!r}"
    )

    # Effect absent: nothing was written by the rejected call.
    scan = ddb.scan(TableName=table, ConsistentRead=True)
    assert scan["Count"] == 0, "rejected PutItem still persisted an item"

    # Positive control: a correctly-typed PutItem on the same table succeeds.
    good_pk = ctx.unique_name("item-")
    ddb.put_item(TableName=table, Item={"pk": {"S": good_pk}, "note": {"S": "good"}})
    got = ddb.get_item(TableName=table, Key={"pk": {"S": good_pk}}, ConsistentRead=True)
    assert got.get("Item") is not None, "positive control PutItem did not persist"
    note = got["Item"]["note"]["S"]
    assert note == "good", f"expected note='good', got {note!r}"


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    return name


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
