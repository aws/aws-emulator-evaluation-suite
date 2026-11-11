"""lsi-query-sort-key-operand-type-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lsi-query-sort-key-operand-type-mismatch-rejected"
GROUP = "lsi"
SERVICES = ["dynamodb"]


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call unexpectedly succeeded where an error was required: {resp!r}")


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Query against an LSI rejects begins_with given an N operand with a ValidationException
    naming the function and the operand type, while the correctly-typed S operand still selects
    on the index.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-lsitype-")
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "lsiSk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        LocalSecondaryIndexes=[{
            "IndexName": "lsi-type",
            "KeySchema": [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "lsiSk", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "KEYS_ONLY"},
        }],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={"pk": {"S": "item-1"}, "sk": {"S": "rev-0"}, "lsiSk": {"S": "alpha"}})
    ddb.put_item(TableName=table, Item={"pk": {"S": "item-1"}, "sk": {"S": "rev-1"}, "lsiSk": {"S": "beta"}})

    code, message = _error(lambda: ddb.query(
        TableName=table, IndexName="lsi-type",
        KeyConditionExpression="pk = :pk AND begins_with(lsiSk, :v)",
        ExpressionAttributeValues={":pk": {"S": "item-1"}, ":v": {"N": "1"}},
    ))
    assert code == "ValidationException", (
        f"begins_with(lsiSk, N-operand) on the LSI answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    expected_message = (
        "Invalid KeyConditionExpression: Incorrect operand type for operator or function; "
        "operator or function: begins_with, operand type: N"
    )
    assert message == expected_message, (
        f"the refusal message is {message!r}, expected {expected_message!r}"
    )

    resp = ddb.query(
        TableName=table, IndexName="lsi-type",
        KeyConditionExpression="pk = :pk AND begins_with(lsiSk, :v)",
        ExpressionAttributeValues={":pk": {"S": "item-1"}, ":v": {"S": "al"}},
        ConsistentRead=True,
    )
    got = [item["sk"]["S"] for item in resp["Items"]]
    assert got == ["rev-0"], (
        f"begins_with(lsiSk, 'al') with the correctly-typed S operand returned {got!r}, expected "
        f"['rev-0']"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
