"""partiql-update-set-list-append-non-list-literal-operand-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-update-set-list-append-non-list-literal-operand-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _stored(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PartiQL UPDATE SET's list_append refuses a non-list literal operand with
    ValidationException and leaves the stored list untouched; a list literal operand succeeds.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlapprej-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    key = {"pk": {"S": "u1"}}
    ddb.put_item(TableName=table, Item={**key, "l": {"L": [{"N": "1"}, {"N": "2"}]}})

    code, message = _error(lambda: ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET l = list_append(l, 3) WHERE pk = ?',
        Parameters=[{"S": "u1"}],
    ))
    assert code == "ValidationException", (
        f"list_append with a Number literal operand answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    expected = (
        "Incorrect operand type for operator or function; operator or function: list_append, "
        "operand type: N"
    )
    assert message == expected, f"list_append refusal message is {message!r}, expected {expected!r}"
    after_refusal = _stored(ddb, table, "u1")
    assert after_refusal["l"] == {"L": [{"N": "1"}, {"N": "2"}]}, (
        f"after the refused list_append the stored list is {after_refusal.get('l')!r}, expected "
        f"the original [1, 2] untouched"
    )

    # Positive control: the identical statement with a list literal operand succeeds.
    ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET l = list_append(l, [3]) WHERE pk = ?',
        Parameters=[{"S": "u1"}],
    )
    accepted = _stored(ddb, table, "u1")
    assert accepted["l"] == {"L": [{"N": "1"}, {"N": "2"}, {"N": "3"}]}, (
        f"list_append(l, [3]) after the refusal stored {accepted.get('l')!r}, expected [1, 2, 3]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
