"""number-set-add-type-mismatch-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "number-set-add-type-mismatch-rejected"
GROUP = "representation"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem ADD of a Number Set (NS) value onto an existing String Set (SS)
    attribute is rejected with ValidationException, the attribute is left unchanged,
    and an ADD of a same-typed (SS) value on the same attribute still succeeds."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx)

    pk = ctx.unique_name("item-")
    ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "tags": {"SS": ["a", "b"]}})

    err = _error(
        lambda: ddb.update_item(
            TableName=table,
            Key={"pk": {"S": pk}},
            UpdateExpression="ADD tags :n",
            ExpressionAttributeValues={":n": {"NS": ["1"]}},
        )
    )
    assert err.get("Code") == "ValidationException", (
        f"expected ValidationException, got {err.get('Code')!r}"
    )
    expected = "An operand in the update expression has an incorrect data type"
    assert err.get("Message") == expected, (
        f"expected message {expected!r}, got {err.get('Message')!r}"
    )

    # Effect absent: the attribute is untouched by the rejected mismatched ADD.
    item = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
    assert set(item["tags"]["SS"]) == {"a", "b"}, "SS attribute was mutated by rejected ADD"

    # Positive control: a same-typed ADD on the same attribute still succeeds.
    ddb.update_item(
        TableName=table,
        Key={"pk": {"S": pk}},
        UpdateExpression="ADD tags :n",
        ExpressionAttributeValues={":n": {"SS": ["c"]}},
    )
    item = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
    assert set(item["tags"]["SS"]) == {"a", "b", "c"}, "positive-control ADD did not apply"


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    return name


def _error(fn):
    """The Error dict of a call that MUST be refused; RAISES if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
