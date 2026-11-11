"""partiql-write-and-transaction-condition-function-ccf."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-write-and-transaction-condition-function-ccf"
GROUP = "partiql"
SERVICES = ["dynamodb"]
_CCF = ("ConditionalCheckFailedException", "The conditional request failed")
_CANCELED = (
    "TransactionCanceledException",
    "Transaction cancelled, please refer cancellation reasons for specific reasons [ConditionalCheckFailed]",
)


def _table(ctx) -> str:
    """A pk/sk table for PartiQL write statements."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-pqlwc-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    return name


def _item(ddb, table, pk, sk):
    return ddb.get_item(
        TableName=table, Key={"pk": {"S": pk}, "sk": {"S": sk}}, ConsistentRead=True,
    ).get("Item")


def expect_error(fn, code, message):
    """Call fn(); assert it raises exactly (code, message). An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, f"expected {code!r}, got {err.get('Code')!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected the call to be refused with {code!r}, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL write WHERE condition built from NOT begins_with or attribute_exists applies when it
    holds, else fails (ConditionalCheckFailedException, or TransactionCanceledException inside
    ExecuteTransaction) with the item unchanged; attribute_not_exists(pk) never creates an absent key.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.delete.html
    https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.multiplestatements.transactions.html
    """
    ddb = ctx.client("dynamodb")
    t = _table(ctx)

    # DELETE WHERE pk AND NOT begins_with(sk, ...): true branch deletes, proven by a read.
    ddb.put_item(TableName=t, Item={"pk": {"S": "p2"}, "sk": {"S": "c1"}})
    deleted = ddb.execute_statement(
        Statement=f'DELETE FROM "{t}" WHERE pk=\'p2\' AND sk=\'c1\' AND NOT begins_with("sk", \'z\') '
                  'RETURNING ALL OLD *'
    )
    assert deleted["Items"] == [{"pk": {"S": "p2"}, "sk": {"S": "c1"}}], (
        f"DELETE with a true NOT begins_with condition must apply, got {deleted['Items']!r}"
    )
    assert _item(ddb, t, "p2", "c1") is None, "the deleted item must be gone"

    # False branch: NOT begins_with(sk, 'a') is false when sk begins with 'a', so the DELETE is
    # refused with ConditionalCheckFailedException and the item is left in place.
    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "a1"}, "flag": {"S": "active"}})
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f'DELETE FROM "{t}" WHERE pk=\'p1\' AND sk=\'a1\' AND NOT begins_with("sk", \'a\')'
        ),
        *_CCF,
    )
    assert _item(ddb, t, "p1", "a1") == {"pk": {"S": "p1"}, "sk": {"S": "a1"}, "flag": {"S": "active"}}, (
        "a failed conditional DELETE must leave the item untouched"
    )

    # UPDATE of a key the table never held, guarded by attribute_not_exists(pk): the write is
    # refused with ConditionalCheckFailedException and creates nothing.
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f'UPDATE "{t}" SET v = ? WHERE pk=\'absent\' AND sk=\'absent\' '
                      'AND attribute_not_exists(pk)',
            Parameters=[{"N": "1"}],
        ),
        *_CCF,
    )
    assert _item(ddb, t, "absent", "absent") is None, (
        "a refused UPDATE guarded by attribute_not_exists(pk) on an absent key must create nothing"
    )

    # ExecuteTransaction UPDATE conditioned on attribute_exists: true branch commits, proven by a
    # read; false branch cancels the whole transaction with the exact reason, item unchanged.
    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "a2"}, "m": {"M": {"sub": {"S": "x"}}}})
    ddb.execute_transaction(TransactStatements=[{
        "Statement": f'UPDATE "{t}" SET v = ? WHERE pk=\'p1\' AND sk=\'a2\' AND attribute_exists(m)',
        "Parameters": [{"N": "2"}],
    }])
    assert _item(ddb, t, "p1", "a2") == {
        "pk": {"S": "p1"}, "sk": {"S": "a2"}, "m": {"M": {"sub": {"S": "x"}}}, "v": {"N": "2"},
    }, "the transaction UPDATE must have applied v=2 once attribute_exists(m) held"

    expect_error(
        lambda: ddb.execute_transaction(TransactStatements=[{
            "Statement": f'UPDATE "{t}" SET v = ? WHERE pk=\'p1\' AND sk=\'a1\' AND attribute_exists(m)',
            "Parameters": [{"N": "3"}],
        }]),
        *_CANCELED,
    )
    assert _item(ddb, t, "p1", "a1") == {"pk": {"S": "p1"}, "sk": {"S": "a1"}, "flag": {"S": "active"}}, (
        "a cancelled transaction UPDATE must leave the item untouched"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
