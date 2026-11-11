"""transact-write-items-unused-expression-attribute-value-on-second-action-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-unused-expression-attribute-value-on-second-action-rejected"
GROUP = 'transactions'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
_EXPECTED_MESSAGE = 'Value provided in ExpressionAttributeValues unused in expressions: keys: {:extra}'


def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'call unexpectedly SUCCEEDED where ValidationException was required: {result!r}')


def _second_action_with_stray_value(kind: str, table: str) -> dict:
    """A second TransactItems entry of *kind* carrying one unused ExpressionAttributeValues entry."""
    if kind == 'Update':
        return {'Update': {
            'TableName': table, 'Key': {'pk': {'S': 'target'}},
            'UpdateExpression': 'SET v = :v',
            'ExpressionAttributeValues': {':v': {'N': '1'}, ':extra': {'N': '9'}},
        }}
    if kind == 'Put':
        return {'Put': {
            'TableName': table, 'Item': {'pk': {'S': 'target'}},
            'ConditionExpression': 'attribute_not_exists(pk) OR :x = :x',
            'ExpressionAttributeValues': {':x': {'S': 'z'}, ':extra': {'N': '9'}},
        }}
    if kind == 'Delete':
        return {'Delete': {
            'TableName': table, 'Key': {'pk': {'S': 'target'}},
            'ConditionExpression': 'attribute_exists(pk)',
            'ExpressionAttributeValues': {':extra': {'N': '9'}},
        }}
    return {'ConditionCheck': {
        'TableName': table, 'Key': {'pk': {'S': 'target'}},
        'ConditionExpression': 'attribute_exists(pk)',
        'ExpressionAttributeValues': {':extra': {'N': '9'}},
    }}


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'dp:api', 'plane:data')
def run(ctx) -> None:
    """An ExpressionAttributeValues entry no expression references is rejected whole even when it
    sits only on the second of two TransactWriteItems actions; the first, valid action does not
    commit either.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'target'}})

    # Positive control: the same four kinds, minus the stray entry, commit as the second action.
    for kind in ('Put', 'Update', 'Delete', 'ConditionCheck'):
        first_key = f'control-first-{kind}'
        if kind == 'Put':
            second = {'Put': {
                'TableName': table, 'Item': {'pk': {'S': 'target'}, 'touched': {'S': kind}},
            }}
        elif kind == 'Update':
            second = {'Update': {
                'TableName': table, 'Key': {'pk': {'S': 'target'}},
                'UpdateExpression': 'SET v = :v', 'ExpressionAttributeValues': {':v': {'N': '1'}},
            }}
        elif kind == 'Delete':
            second = {'Delete': {
                'TableName': table, 'Key': {'pk': {'S': f'to-delete-{kind}'}},
            }}
            ddb.put_item(TableName=table, Item={'pk': {'S': f'to-delete-{kind}'}})
        else:
            second = {'ConditionCheck': {
                'TableName': table, 'Key': {'pk': {'S': 'target'}},
                'ConditionExpression': 'attribute_exists(pk)',
            }}
        ddb.transact_write_items(TransactItems=[
            {'Put': {'TableName': table, 'Item': {'pk': {'S': first_key}}}},
            second,
        ])
        got = ddb.get_item(TableName=table, Key={'pk': {'S': first_key}}, ConsistentRead=True)
        assert 'Item' in got, f'positive control for {kind}: first action {first_key!r} must commit'

    for kind in ('Put', 'Update', 'Delete', 'ConditionCheck'):
        first_key = f'rejected-first-{kind}'
        first = {'Put': {'TableName': table, 'Item': {'pk': {'S': first_key}}}}
        second = _second_action_with_stray_value(kind, table)
        code, message = _error(lambda first=first, second=second: ddb.transact_write_items(
            TransactItems=[first, second],
        ))
        assert code == ERR_VALIDATION, (
            f'a stray ExpressionAttributeValues entry on the second ({kind}) action answered '
            f'{code!r} ({message!r}), expected {ERR_VALIDATION}'
        )
        assert message == _EXPECTED_MESSAGE, (
            f'second action {kind}: expected message {_EXPECTED_MESSAGE!r}, got {message!r}'
        )
        got = ddb.get_item(TableName=table, Key={'pk': {'S': first_key}}, ConsistentRead=True)
        assert 'Item' not in got, (
            f'a transaction rejected for a stray ExpressionAttributeValues entry on its second '
            f'({kind}) action must not write its first action either, got {got.get("Item")!r}'
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
