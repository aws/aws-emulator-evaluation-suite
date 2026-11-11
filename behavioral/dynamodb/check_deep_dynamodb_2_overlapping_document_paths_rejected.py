"""deep-dynamodb-2-overlapping-document-paths-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-dynamodb-2-overlapping-document-paths-rejected"
GROUP = 'update-expression'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
MSG_OVERLAP_A_B__A = (
    '1 validation error detected: Invalid UpdateExpression: Two document paths overlap with each '
    'other; must remove or rewrite one of these paths; path one: [a, b], path two: [a]'
)
MSG_OVERLAP_AB__ABC = (
    '1 validation error detected: Invalid UpdateExpression: Two document paths overlap with each '
    'other; must remove or rewrite one of these paths; path one: [a, b], path two: [a, b, c]'
)


def _table(ctx, ddb) -> str:
    name = ctx.unique_name('ddbexpr-')
    ddb.create_table(
        TableName=name,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _stored(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={'pk': {'S': pk}}, ConsistentRead=True).get('Item')


def _error(fn):
    """(code, message) of the ClientError fn raises. Raises if fn SUCCEEDS."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'call was expected to be rejected but succeeded: {resp!r}')


@tags(
    "dp:api",
    "plane:data",
    "concern:data-plane",
    "concern:negative-classes",
    "axis:rejection",
    "cap:c1",
)
def run(ctx) -> None:
    """`SET a.b = :v REMOVE a` and `SET a.b = :v, a.b.c = :w` each raise ValidationException with the exact overlap
    message and change nothing, while each clause on its own succeeds against the same item.
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)
    key = {'pk': {'S': 'k'}}
    original = {'pk': {'S': 'k'}, 'a': {'M': {'b': {'N': '1'}}}}
    ddb.put_item(TableName=t, Item=original)

    code, msg = _error(lambda: ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='SET a.b = :v REMOVE a',
        ExpressionAttributeValues={':v': {'N': '2'}},
    ))
    assert code == ERR_VALIDATION, f'SET a.b REMOVE a: expected {ERR_VALIDATION}, got {code!r} ({msg!r})'
    assert msg == MSG_OVERLAP_A_B__A, f'SET a.b REMOVE a: expected {MSG_OVERLAP_A_B__A!r}, got {msg!r}'
    after = _stored(ddb, t, 'k')
    assert after == original, f'rejected update changed the item: {after!r} (was {original!r})'

    code, msg = _error(lambda: ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='SET a.b = :v, a.b.c = :w',
        ExpressionAttributeValues={':v': {'N': '2'}, ':w': {'N': '3'}},
    ))
    assert code == ERR_VALIDATION, f'SET a.b, a.b.c: expected {ERR_VALIDATION}, got {code!r} ({msg!r})'
    assert msg == MSG_OVERLAP_AB__ABC, f'SET a.b, a.b.c: expected {MSG_OVERLAP_AB__ABC!r}, got {msg!r}'
    after = _stored(ddb, t, 'k')
    assert after == original, f'rejected update changed the item: {after!r} (was {original!r})'

    # Positive controls: each clause alone is valid on this item.
    ddb.update_item(TableName=t, Key=key, UpdateExpression='SET a.b = :v',
                    ExpressionAttributeValues={':v': {'N': '2'}})
    after = _stored(ddb, t, 'k')
    assert after == {'pk': {'S': 'k'}, 'a': {'M': {'b': {'N': '2'}}}}, f'SET a.b alone stored {after!r}'
    ddb.update_item(TableName=t, Key=key, UpdateExpression='REMOVE a')
    after = _stored(ddb, t, 'k')
    assert after == {'pk': {'S': 'k'}}, f'REMOVE a alone stored {after!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
