"""deep-dynamodb-2-set-nested-path-on-missing-parent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-dynamodb-2-set-nested-path-on-missing-parent-rejected"
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
    """SET parent.child is rejected when `parent` is absent; DynamoDB does not auto-vivify maps.

    The item stays unchanged, and the same expression succeeds where `parent` is a map.
    """
    ddb = ctx.client('dynamodb')
    t = _table(ctx, ddb)
    expr = 'SET parent.child = :v'
    vals = {':v': {'S': 'q'}}

    # Positive control: same expression, parent exists as an (empty) map.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'has-parent'}, 'parent': {'M': {}}})
    ddb.update_item(TableName=t, Key={'pk': {'S': 'has-parent'}},
                    UpdateExpression=expr, ExpressionAttributeValues=vals)
    ok = _stored(ddb, t, 'has-parent')
    assert ok == {'pk': {'S': 'has-parent'}, 'parent': {'M': {'child': {'S': 'q'}}}}, (
        f'positive control: SET parent.child on an existing map stored {ok!r}'
    )

    # Broken: parent attribute absent.
    original = {'pk': {'S': 'no-parent'}, 'x': {'N': '1'}}
    ddb.put_item(TableName=t, Item=original)
    code, msg = _error(lambda: ddb.update_item(
        TableName=t, Key={'pk': {'S': 'no-parent'}},
        UpdateExpression=expr, ExpressionAttributeValues=vals,
    ))
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code!r} ({msg!r})'
    assert msg == MSG_INVALID_PATH, f'expected message {MSG_INVALID_PATH!r}, got {msg!r}'
    after = _stored(ddb, t, 'no-parent')
    assert after == original, f'rejected update still changed the item: {after!r} (was {original!r})'

    # Same rejection when the item does not exist at all (upsert cannot vivify the parent either).
    code, msg = _error(lambda: ddb.update_item(
        TableName=t, Key={'pk': {'S': 'absent-item'}},
        UpdateExpression=expr, ExpressionAttributeValues=vals,
    ))
    assert code == ERR_VALIDATION, f'absent item: expected {ERR_VALIDATION}, got {code!r} ({msg!r})'
    assert msg == MSG_INVALID_PATH, f'absent item: expected {MSG_INVALID_PATH!r}, got {msg!r}'
    assert _stored(ddb, t, 'absent-item') is None, 'rejected upsert created the item anyway'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
