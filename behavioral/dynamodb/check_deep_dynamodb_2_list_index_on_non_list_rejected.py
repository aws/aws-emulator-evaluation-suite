"""deep-dynamodb-2-list-index-on-non-list-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-dynamodb-2-list-index-on-non-list-rejected"
GROUP = 'update-expression'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
MSG_INVALID_PATH = 'The document path provided in the update expression is invalid for update'


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
    """SET x[0] on a string attribute or an absent one raises ValidationException with the exact message and leaves
    the item unchanged, while SET l[0] on a list attribute of the same item replaces element 0.
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)
    key = {'pk': {'S': 'k'}}
    original = {'pk': {'S': 'k'}, 's': {'S': 'str'}, 'l': _slist(['a', 'b', 'c', 'd', 'e'])}
    ddb.put_item(TableName=t, Item=original)
    vals = {':v': {'S': 'X'}}

    code, msg = _error(lambda: ddb.update_item(
        TableName=t, Key=key, UpdateExpression='SET s[0] = :v', ExpressionAttributeValues=vals,
    ))
    assert code == ERR_VALIDATION, f'SET s[0] on a string: expected {ERR_VALIDATION}, got {code!r} ({msg!r})'
    assert msg == MSG_INVALID_PATH, f'SET s[0] on a string: expected {MSG_INVALID_PATH!r}, got {msg!r}'
    after = _stored(ddb, t, 'k')
    assert after == original, f'rejected update changed the item: {after!r}'

    code, msg = _error(lambda: ddb.update_item(
        TableName=t, Key=key, UpdateExpression='SET nope[0] = :v', ExpressionAttributeValues=vals,
    ))
    assert code == ERR_VALIDATION, f'SET nope[0] on absent attr: expected {ERR_VALIDATION}, got {code!r} ({msg!r})'
    assert msg == MSG_INVALID_PATH, f'SET nope[0] on absent attr: expected {MSG_INVALID_PATH!r}, got {msg!r}'
    after = _stored(ddb, t, 'k')
    assert after == original, f'rejected update changed the item: {after!r}'
    assert 'nope' not in after, f'rejected update created attribute nope: {after!r}'

    # Positive control: the same form on the real list in the same item.
    ddb.update_item(TableName=t, Key=key, UpdateExpression='SET l[0] = :v', ExpressionAttributeValues=vals)
    after = _stored(ddb, t, 'k')
    assert after['l'] == _slist(['X', 'b', 'c', 'd', 'e']), f'SET l[0] on a list stored {after!r}'
    assert after['s'] == {'S': 'str'}, f'string attribute changed: {after!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
