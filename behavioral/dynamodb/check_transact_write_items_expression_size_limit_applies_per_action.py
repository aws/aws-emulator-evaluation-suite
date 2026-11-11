"""transact-write-items-expression-size-limit-applies-per-action."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-expression-size-limit-applies-per-action"
GROUP = 'transactions'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
_MAX = 4096
_COND_TOO_LONG = 'Invalid ConditionExpression: Expression size has exceeded the maximum allowed size;'
_UPDATE_TOO_LONG = 'Invalid UpdateExpression: Expression size has exceeded the maximum allowed size;'


def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'call unexpectedly SUCCEEDED where ValidationException was required: {result!r}')


def _condition_of_len(total: int) -> str:
    """An `attribute_not_exists(<padding>)` condition exactly `total` bytes, true for every item."""
    prefix, suffix = 'attribute_not_exists(', ')'
    expr = prefix + 'a' * (total - len(prefix) - len(suffix)) + suffix
    assert len(expr) == total, len(expr)
    return expr


def _update_of_len(total: int) -> str:
    """A `SET <padding> = :v` update exactly `total` bytes; `<padding>` is the attribute set."""
    prefix, suffix = 'SET ', ' = :v'
    attr = 'a' * (total - len(prefix) - len(suffix))
    expr = prefix + attr + suffix
    assert len(expr) == total, len(expr)
    return expr, attr


@tags('axis:rejection', 'cap:c2', 'concern:negative-classes', 'dp:api', 'plane:data')
def run(ctx) -> None:
    """The 4 KB expression-size limit applies independently to each TransactWriteItems action:
    a 4096-byte Put condition or Update UpdateExpression commits, a 4097-byte one is a top-level
    ValidationException, and an oversized second action leaves the transaction's first Put unwritten.

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

    # Positive control: a Put whose ConditionExpression is exactly 4096 bytes commits.
    ddb.transact_write_items(TransactItems=[
        {'Put': {
            'TableName': table, 'Item': {'pk': {'S': 'put-accepted'}},
            'ConditionExpression': _condition_of_len(_MAX),
        }},
    ])
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'put-accepted'}}, ConsistentRead=True)
    assert got.get('Item') == {'pk': {'S': 'put-accepted'}}, (
        f'positive control: a 4096-byte Put ConditionExpression must commit, got {got.get("Item")!r}'
    )

    # Positive control: an Update whose UpdateExpression is exactly 4096 bytes commits.
    update_expr, update_attr = _update_of_len(_MAX)
    ddb.transact_write_items(TransactItems=[
        {'Update': {
            'TableName': table, 'Key': {'pk': {'S': 'update-accepted'}},
            'UpdateExpression': update_expr,
            'ExpressionAttributeValues': {':v': {'S': 'ok'}},
        }},
    ])
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'update-accepted'}}, ConsistentRead=True)
    assert got.get('Item', {}).get(update_attr) == {'S': 'ok'}, (
        f'positive control: a 4096-byte Update UpdateExpression must commit, got {got.get("Item")!r}'
    )

    # Negative: a ConditionCheck whose ConditionExpression is 4097 bytes is a top-level ValidationException.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'cc-target'}})
    code, message = _error(lambda: ddb.transact_write_items(TransactItems=[
        {'ConditionCheck': {
            'TableName': table, 'Key': {'pk': {'S': 'cc-target'}},
            'ConditionExpression': _condition_of_len(_MAX + 1),
        }},
    ]))
    assert code == ERR_VALIDATION, f'oversized ConditionCheck condition answered {code!r} ({message!r})'
    assert message == _COND_TOO_LONG, f'oversized ConditionCheck condition message was {message!r}'

    # Negative: a Delete whose ConditionExpression is 4097 bytes is a top-level ValidationException,
    # and the item it would have deleted survives.
    ddb.put_item(TableName=table, Item={'pk': {'S': 'del-target'}})
    code, message = _error(lambda: ddb.transact_write_items(TransactItems=[
        {'Delete': {
            'TableName': table, 'Key': {'pk': {'S': 'del-target'}},
            'ConditionExpression': _condition_of_len(_MAX + 1),
        }},
    ]))
    assert code == ERR_VALIDATION, f'oversized Delete condition answered {code!r} ({message!r})'
    assert message == _COND_TOO_LONG, f'oversized Delete condition message was {message!r}'
    got = ddb.get_item(TableName=table, Key={'pk': {'S': 'del-target'}}, ConsistentRead=True)
    assert got.get('Item') == {'pk': {'S': 'del-target'}}, (
        f'a Delete rejected for an oversized ConditionExpression must not remove its item, got {got.get("Item")!r}'
    )

    # Negative: an Update whose UpdateExpression is 4097 bytes is a top-level ValidationException.
    update_over, _ = _update_of_len(_MAX + 1)
    code, message = _error(lambda: ddb.transact_write_items(TransactItems=[
        {'Update': {
            'TableName': table, 'Key': {'pk': {'S': 'upd-target'}},
            'UpdateExpression': update_over,
            'ExpressionAttributeValues': {':v': {'S': 'x'}},
        }},
    ]))
    assert code == ERR_VALIDATION, f'oversized Update UpdateExpression answered {code!r} ({message!r})'
    assert message == _UPDATE_TOO_LONG, f'oversized Update UpdateExpression message was {message!r}'

    # An oversized SECOND action refuses the whole call; the first action's Put never commits.
    first_key = 'second-member-oversized-first-put'
    code, message = _error(lambda: ddb.transact_write_items(TransactItems=[
        {'Put': {'TableName': table, 'Item': {'pk': {'S': first_key}}}},
        {'ConditionCheck': {
            'TableName': table, 'Key': {'pk': {'S': 'cc-target'}},
            'ConditionExpression': _condition_of_len(_MAX + 1),
        }},
    ]))
    assert code == ERR_VALIDATION, f'oversized second action answered {code!r} ({message!r})'
    assert message == _COND_TOO_LONG, f'oversized second action message was {message!r}'
    got = ddb.get_item(TableName=table, Key={'pk': {'S': first_key}}, ConsistentRead=True)
    assert 'Item' not in got, (
        f'a transaction rejected for its oversized second action must not write its first Put, '
        f'got {got.get("Item")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
