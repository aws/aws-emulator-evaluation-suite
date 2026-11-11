"""transact-write-items-invalid-table-name-names-member-path."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-invalid-table-name-names-member-path"
GROUP = 'transactions'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'

_BAD_NAME = 'bad name'
_ACTION_PATH = {'Put': 'put', 'Update': 'update', 'Delete': 'delete', 'ConditionCheck': 'conditionCheck'}


def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'call unexpectedly SUCCEEDED where ValidationException was required: {result!r}')


def _bad_action(kind: str, table_name: str) -> dict:
    """A single TransactItems entry of *kind* addressing *table_name*."""
    if kind == 'Put':
        return {'Put': {'TableName': table_name, 'Item': {'pk': {'S': 'victim'}}}}
    if kind == 'Update':
        return {'Update': {
            'TableName': table_name, 'Key': {'pk': {'S': 'victim'}},
            'UpdateExpression': 'SET v = :v',
            'ExpressionAttributeValues': {':v': {'N': '1'}},
        }}
    if kind == 'Delete':
        return {'Delete': {'TableName': table_name, 'Key': {'pk': {'S': 'victim'}}}}
    return {'ConditionCheck': {
        'TableName': table_name, 'Key': {'pk': {'S': 'victim'}},
        'ConditionExpression': 'attribute_not_exists(pk)',
    }}


def _sibling(table: str) -> dict:
    """A valid Put used to fill the position the bad action does not occupy."""
    return {'Put': {'TableName': table, 'Item': {'pk': {'S': 'sibling'}}}}


@tags('axis:rejection', 'cap:c1', 'concern:negative-classes', 'dp:api', 'plane:data')
def run(ctx) -> None:
    """A TransactWriteItems action whose TableName violates the name pattern is a top-level
    ValidationException naming the member path by position and kind; the whole transaction,
    including its valid sibling action, writes nothing.

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

    # Positive control: a normal two-item transaction commits, so every rejection below is
    # attributable to the bad TableName rather than to the harness being unable to transact at all.
    ddb.transact_write_items(TransactItems=[
        {'Put': {'TableName': table, 'Item': {'pk': {'S': 'control-a'}}}},
        {'Put': {'TableName': table, 'Item': {'pk': {'S': 'control-b'}}}},
    ])
    for key in ('control-a', 'control-b'):
        got = ddb.get_item(TableName=table, Key={'pk': {'S': key}}, ConsistentRead=True)
        assert 'Item' in got, f'positive control: {key!r} should have been written by a valid transaction'

    for kind in ('Put', 'Update', 'Delete', 'ConditionCheck'):
        for position in (1, 2):
            bad = _bad_action(kind, _BAD_NAME)
            sibling = _sibling(table)
            items = [bad, sibling] if position == 1 else [sibling, bad]
            code, message = _error(lambda items=items: ddb.transact_write_items(TransactItems=items))
            assert code == ERR_VALIDATION, (
                f'{kind} with an invalid TableName at position {position} answered {code!r} '
                f'({message!r}), expected {ERR_VALIDATION}'
            )
            path = f'transactItems.{position}.member.{_ACTION_PATH[kind]}.tableName'
            expected = (
                f"1 validation error detected: Value '{_BAD_NAME}' at '{path}' failed to satisfy "
                f"constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+"
            )
            assert message == expected, (
                f'{kind} at position {position}: expected message {expected!r}, got {message!r}'
            )

    # Effect absent: none of the 8 rejected transactions wrote their valid sibling action.
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'sibling'}}, ConsistentRead=True)
    assert 'Item' not in got, (
        f'a transaction rejected for an invalid TableName must not write its sibling action, '
        f'got {got.get("Item")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
