"""execute-statement-update-missing-sort-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-update-missing-sort-key-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_MISSING_KEY = ("ValidationException",
                "Where clause does not contain a mandatory equality on all key attributes")


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ExecuteStatement to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


def _stored(ddb, table, pk, sk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}, "sk": {"S": sk}},
                        ConsistentRead=True).get("Item")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a composite-key table, a PartiQL UPDATE whose WHERE omits the sort key is a
    ValidationException naming the missing key equality, and no item is created.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbupdwc-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                   {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    ddb.put_item(TableName=table, Item={"pk": {"S": "x"}, "sk": {"S": "y"}, "a": {"N": "0"}})

    # The WHERE clause names the hash key but omits the sort key: AWS rejects the whole
    # statement rather than treating it as a prefix match over the partition.
    expect_error(
        lambda: ddb.execute_statement(Statement=f"UPDATE \"{table}\" SET a=1 WHERE pk='x'"),
        *_MISSING_KEY,
    )
    unseeded = _stored(ddb, table, "x", "y")
    assert unseeded == {"pk": {"S": "x"}, "sk": {"S": "y"}, "a": {"N": "0"}}, (
        f"a rejected UPDATE changed the existing item: {unseeded!r}"
    )
    partition = ddb.query(TableName=table, KeyConditionExpression="pk = :p",
                          ExpressionAttributeValues={":p": {"S": "x"}}, ConsistentRead=True)["Items"]
    assert partition == [unseeded], (
        f"a rejected UPDATE created another item under partition key 'x': {partition!r}"
    )

    # Positive control: the identical SET succeeds once the WHERE names both key attributes.
    ddb.execute_statement(Statement=f"UPDATE \"{table}\" SET a=1 WHERE pk='x' AND sk='y'")
    updated = _stored(ddb, table, "x", "y")
    assert updated == {"pk": {"S": "x"}, "sk": {"S": "y"}, "a": {"N": "1"}}, (
        f"UPDATE with both key attributes in WHERE did not land: {updated!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
