"""deep-dynamodb-2-same-list-index-in-two-clauses-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-dynamodb-2-same-list-index-in-two-clauses-rejected"
GROUP = 'update-expression'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
MSG_OVERLAP_L1 = (
    '1 validation error detected: Invalid UpdateExpression: Two document paths overlap with each '
    'other; must remove or rewrite one of these paths; path one: [l, [1]], path two: [l, [1]]'
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


def _slist(values):
    return {'L': [{'S': v} for v in values]}


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
    """Naming one list index in two clauses (REMOVE l[1] SET l[1]; REMOVE l[1], l[1]) is rejected.

    The message renders the index as `[l, [1]]`; the item is unchanged after each rejection,
    and each clause alone works.
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)
    key = {'pk': {'S': 'k'}}
    original = {'pk': {'S': 'k'}, 'l': _slist(['a', 'b', 'c', 'd', 'e'])}
    ddb.put_item(TableName=t, Item=original)

    code, msg = _error(lambda: ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='REMOVE l[1] SET l[1] = :v',
        ExpressionAttributeValues={':v': {'S': 'X'}},
    ))
    assert code == ERR_VALIDATION, f'REMOVE l[1] SET l[1]: expected {ERR_VALIDATION}, got {code!r} ({msg!r})'
    assert msg == MSG_OVERLAP_L1, f'REMOVE l[1] SET l[1]: expected {MSG_OVERLAP_L1!r}, got {msg!r}'
    after = _stored(ddb, t, 'k')
    assert after == original, f'rejected update changed the item: {after!r}'

    code, msg = _error(lambda: ddb.update_item(
        TableName=t, Key=key, UpdateExpression='REMOVE l[1], l[1]',
    ))
    assert code == ERR_VALIDATION, f'REMOVE l[1], l[1]: expected {ERR_VALIDATION}, got {code!r} ({msg!r})'
    assert msg == MSG_OVERLAP_L1, f'REMOVE l[1], l[1]: expected {MSG_OVERLAP_L1!r}, got {msg!r}'
    after = _stored(ddb, t, 'k')
    assert after == original, f'rejected update changed the item: {after!r}'

    # Positive controls: each clause alone is valid.
    ddb.update_item(TableName=t, Key=key, UpdateExpression='SET l[1] = :v',
                    ExpressionAttributeValues={':v': {'S': 'X'}})
    after = _stored(ddb, t, 'k')
    assert after['l'] == _slist(['a', 'X', 'c', 'd', 'e']), f'SET l[1] alone stored {after!r}'
    ddb.update_item(TableName=t, Key=key, UpdateExpression='REMOVE l[1]')
    after = _stored(ddb, t, 'k')
    assert after['l'] == _slist(['a', 'c', 'd', 'e']), f'REMOVE l[1] alone stored {after!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
