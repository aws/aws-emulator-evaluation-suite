"""partiql-delete-noop-on-absent-key-and-update-from-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-delete-noop-on-absent-key-and-update-from-rejected"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_EXPECTED_UPDATE_FROM_MESSAGE = "Statement wasn't well formed, can't be processed: Expected data manipulation"


def _stored(ddb, table, pk, sk):
    return ddb.get_item(
        TableName=table, Key={'pk': {'S': pk}, 'sk': {'S': sk}}, ConsistentRead=True,
    ).get('Item')


def _error(fn):
    """The (Code, Message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error'].get('Message')
    raise AssertionError(f'expected the statement to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL DELETE on a key the table does not hold is a no-op even with an extra non-key
    predicate in WHERE, and an UPDATE that places a FROM clause before SET/WHERE is rejected as
    malformed, leaving the stored item untouched in both cases.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.delete.html
    https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlfromdel-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 60})

    item = {'pk': {'S': 'p1'}, 'sk': {'S': 's1'}, 'status': {'S': 'active'}}
    ddb.put_item(TableName=table, Item=item)

    # 1. DELETE on a key the table never held, carrying an extra non-key predicate: the
    # key-not-found outcome wins over the predicate, so the statement succeeds as a no-op.
    r1 = ddb.execute_statement(
        Statement=f"DELETE FROM \"{table}\" "
                  f"WHERE pk = 'absent' AND sk = 'absent' AND status = 'active' RETURNING ALL OLD *")
    assert r1['Items'] == [], (
        f'DELETE on an absent key with an extra non-key predicate must be a no-op, got {r1["Items"]!r}'
    )
    assert _stored(ddb, table, 'p1', 's1') == item, (
        f'the unrelated existing item must be untouched, got {_stored(ddb, table, "p1", "s1")!r}'
    )

    # 2. UPDATE that places a FROM clause before SET/WHERE: the statement is not well formed and
    # is rejected without touching the item SET would have modified.
    code, message = _error(
        lambda: ddb.execute_statement(
            Statement=f"UPDATE \"{table}\" FROM \"{table}\" SET status = 'changed' "
                      f"WHERE pk = 'p1' AND sk = 's1'"))
    assert code == 'ValidationException', (
        f'UPDATE with FROM before SET/WHERE must be refused with ValidationException, got {code!r}'
    )
    assert message == _EXPECTED_UPDATE_FROM_MESSAGE, (
        f'expected message {_EXPECTED_UPDATE_FROM_MESSAGE!r}, got {message!r}'
    )
    assert _stored(ddb, table, 'p1', 's1') == item, (
        f'the rejected UPDATE must leave the item untouched, got {_stored(ddb, table, "p1", "s1")!r}'
    )

    # Positive control: the same UPDATE without the FROM clause, and the same DELETE against the
    # key it actually holds, both succeed.
    ddb.execute_statement(Statement=f"UPDATE \"{table}\" SET status = 'changed' WHERE pk = 'p1' AND sk = 's1'")
    changed = {**item, 'status': {'S': 'changed'}}
    assert _stored(ddb, table, 'p1', 's1') == changed, (
        f'the well-formed UPDATE must have applied, got {_stored(ddb, table, "p1", "s1")!r}'
    )
    r2 = ddb.execute_statement(
        Statement=f"DELETE FROM \"{table}\" WHERE pk = 'p1' AND sk = 's1' RETURNING ALL OLD *")
    assert r2['Items'] == [changed], (
        f'DELETE against the key it actually holds must remove it and return {[changed]!r}, '
        f'got {r2["Items"]!r}'
    )
    assert _stored(ddb, table, 'p1', 's1') is None, (
        f'the item must be gone after the successful DELETE, got {_stored(ddb, table, "p1", "s1")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
