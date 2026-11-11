"""execute-statement-ordering-comparison-rejects-parameterized-boolean-operand."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-ordering-comparison-rejects-parameterized-boolean-operand"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-pqlboolparam-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return ddb, name


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement rejects a '<' comparison whose operand is a Boolean value bound through
    the Parameters list, with the same ValidationException an inline literal operand gets, and a
    rejected UPDATE's WHERE clause writes nothing.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-operators.html
    """
    ddb, table = _table(ctx)

    item = {"pk": {"S": "row"}, "num": {"N": "5"}}
    ddb.put_item(TableName=table, Item=item)

    # Positive control: the same parameterized comparator with an orderable (Number) operand
    # succeeds, so a rejection below is attributable to the Boolean operand, not to '?' binding.
    control = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE pk = ? AND num < ?',
        Parameters=[{"S": "row"}, {"N": "10"}],
        ConsistentRead=True,
    )
    assert control["Items"] == [item], f"positive control returned {control['Items']!r}, expected [{item!r}]"

    code, message = _error(lambda: ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE pk = ? AND num < ?',
        Parameters=[{"S": "row"}, {"BOOL": True}],
        ConsistentRead=True,
    ))
    assert code == "ValidationException", f"'<' against a parameterized BOOL operand gave code {code!r}"
    expected = "Incorrect operand type for operator or function; operator or function: <, operand type: BOOL"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(lambda: ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET other = ? WHERE pk = ? AND num < ?',
        Parameters=[{"N": "1"}, {"S": "row"}, {"BOOL": True}],
    ))
    assert code == "ValidationException", f"UPDATE with a rejected WHERE clause gave code {code!r}"
    assert message == expected, f"UPDATE: expected message {expected!r}, got {message!r}"

    after = ddb.get_item(TableName=table, Key={"pk": {"S": "row"}}, ConsistentRead=True)["Item"]
    assert after == item, f"item must be unchanged after the rejected statement, got {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
