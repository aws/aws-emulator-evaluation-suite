"""execute-transaction-mixed-read-and-write-statements-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-transaction-mixed-read-and-write-statements-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ExecuteTransaction mixing a read statement (SELECT) with a write statement (UPDATE) is
    rejected before either statement executes; the item the UPDATE targeted is left untouched.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": "s1"}, "data": {"S": "original"}})

    code, message = _error(
        lambda: ddb.execute_transaction(
            TransactStatements=[
                {"Statement": f'SELECT * FROM "{table}" WHERE pk=? AND sk=?', "Parameters": [{"S": "p1"}, {"S": "s1"}]},
                {"Statement": f'UPDATE "{table}" SET data=? WHERE pk=? AND sk=?', "Parameters": [{"S": "changed"}, {"S": "p1"}, {"S": "s1"}]},
            ]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "ExecuteTransaction API does not support both read and write operations in the same request."
    assert message == expected_message, f"unexpected message: {message!r}"

    # Positive control: the targeted item is unchanged after the rejected call.
    item = ddb.get_item(TableName=table, Key={"pk": {"S": "p1"}, "sk": {"S": "s1"}}, ConsistentRead=True)["Item"]
    assert item["data"] == {"S": "original"}, f"a rejected mixed transaction must not apply its UPDATE: {item!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
