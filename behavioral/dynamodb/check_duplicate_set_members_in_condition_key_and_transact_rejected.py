"""duplicate-set-members-in-condition-key-and-transact-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-set-members-in-condition-key-and-transact-rejected"
GROUP = 'representation'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error_code(fn, what: str) -> tuple[str, str]:
    """The AWS error code and message `fn` raises; an unexpected success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'{what}: the call was ACCEPTED with {result!r}; real AWS rejects it')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A duplicate SS/NS/BS member outside an Item -- a ConditionExpression value, a Key, or a
    slot inside Transact*Items -- is rejected ValidationException before evaluation, taking a
    valid sibling slot in the same batch or transaction down with it.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-dupset-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(
        TableName=t, WaiterConfig={'Delay': 1, 'MaxAttempts': 60})

    ddb.put_item(TableName=t, Item={'pk': {'S': 'item1'}, 'other': {'S': 'x'}})
    invalid = 'One or more parameter values were invalid: '
    counted = '1 validation error detected: ' + invalid

    # --- a duplicate in a ConditionExpression value, on PutItem and UpdateItem ---
    code, message = _error_code(lambda: ddb.put_item(
        TableName=t, Item={'pk': {'S': 'item1'}, 'other': {'S': 'y'}},
        ConditionExpression='other = :v', ExpressionAttributeValues={':v': {'SS': ['a', 'a']}},
    ), 'PutItem ConditionExpression value with a duplicate-bearing SS')
    assert code == ERR_VALIDATION, f'PutItem with a duplicate SS condition value: got {code!r}'
    assert message == counted + 'Input collection ["a", "a"] contains duplicates.', (
        f'PutItem with a duplicate SS condition value: got message {message!r}'
    )

    code, message = _error_code(lambda: ddb.update_item(
        TableName=t, Key={'pk': {'S': 'item1'}}, UpdateExpression='SET other = :newval',
        ConditionExpression='contains(:v, other)',
        ExpressionAttributeValues={':v': {'NS': ['1', '1']}, ':newval': {'S': 'z'}},
    ), 'UpdateItem ConditionExpression value with a duplicate-bearing NS')
    assert code == ERR_VALIDATION, f'UpdateItem with a duplicate NS condition value: got {code!r}'
    assert message == counted + 'Input collection contains duplicates.', (
        f'UpdateItem with a duplicate NS condition value: got message {message!r}'
    )

    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'item1'}}, ConsistentRead=True)['Item']
    assert got == {'pk': {'S': 'item1'}, 'other': {'S': 'x'}}, (
        f'both rejected conditional writes must leave the item untouched, got {got!r}'
    )

    # --- a duplicate in the Key of GetItem, DeleteItem and BatchGetItem ---
    code, message = _error_code(lambda: ddb.get_item(
        TableName=t, Key={'pk': {'SS': ['a', 'a']}},
    ), 'GetItem Key with a duplicate-bearing SS')
    assert code == ERR_VALIDATION, f'GetItem with a duplicate SS key: got {code!r}'
    assert message == invalid + 'Input collection ["a", "a"] contains duplicates.', (
        f'GetItem with a duplicate SS key: got message {message!r}'
    )

    code, message = _error_code(lambda: ddb.get_item(
        TableName=t, Key={'pk': {'BS': [b'\x01', b'\x01']}},
    ), 'GetItem Key with a duplicate-bearing BS')
    assert code == ERR_VALIDATION, f'GetItem with a duplicate BS key: got {code!r}'
    assert message == invalid + 'Input collection ["AQ==","AQ=="]of type BS contains duplicates.', (
        f'GetItem with a duplicate BS key: got message {message!r}'
    )

    code, message = _error_code(lambda: ddb.delete_item(
        TableName=t, Key={'pk': {'SS': ['b', 'b']}},
    ), 'DeleteItem Key with a duplicate-bearing SS')
    assert code == ERR_VALIDATION, f'DeleteItem with a duplicate SS key: got {code!r}'
    assert message == counted + 'Input collection ["b", "b"] contains duplicates.', (
        f'DeleteItem with a duplicate SS key: got message {message!r}'
    )

    code, message = _error_code(lambda: ddb.batch_get_item(
        RequestItems={t: {'Keys': [{'pk': {'S': 'item1'}}, {'pk': {'NS': ['2', '2']}}]}},
    ), 'BatchGetItem Keys with one duplicate-bearing NS key beside a valid one')
    assert code == ERR_VALIDATION, f'BatchGetItem with a duplicate NS key: got {code!r}'
    assert message == invalid + 'Input collection contains duplicates.', (
        f'BatchGetItem with a duplicate NS key: got message {message!r}'
    )

    # --- a duplicate inside one slot of TransactWriteItems/TransactGetItems rejects the whole
    # call, before any slot -- including a valid sibling -- is evaluated or applied ---
    code, message = _error_code(lambda: ddb.transact_write_items(TransactItems=[
        {'Put': {'TableName': t, 'Item': {'pk': {'S': 'legit-put'}, 'x': {'S': '1'}}}},
        {'Put': {'TableName': t, 'Item': {'pk': {'S': 'bad-put'}, 's': {'SS': ['d', 'd']}}}},
    ]), 'TransactWriteItems with a duplicate-bearing SS in one Put.Item beside a valid Put')
    assert code == ERR_VALIDATION, f'TransactWriteItems with a duplicate SS item: got {code!r}'
    assert message == invalid + 'Input collection ["d", "d"] contains duplicates.', (
        f'TransactWriteItems with a duplicate SS item: got message {message!r}'
    )

    code, message = _error_code(lambda: ddb.transact_write_items(TransactItems=[
        {'Put': {'TableName': t, 'Item': {'pk': {'S': 'legit-check'}, 'x': {'S': '1'}}}},
        {'ConditionCheck': {'TableName': t, 'Key': {'pk': {'S': 'item1'}},
                             'ConditionExpression': 'contains(:v, other)',
                             'ExpressionAttributeValues': {':v': {'BS': [b'\x02', b'\x02']}}}},
    ]), 'TransactWriteItems with a duplicate-bearing BS condition value beside a valid Put')
    assert code == ERR_VALIDATION, f'TransactWriteItems with a duplicate BS condition value: got {code!r}'
    assert message == invalid + 'Input collection ["Ag==","Ag=="]of type BS contains duplicates.', (
        f'TransactWriteItems with a duplicate BS condition value: got message {message!r}'
    )

    code, message = _error_code(lambda: ddb.transact_get_items(TransactItems=[
        {'Get': {'TableName': t, 'Key': {'pk': {'S': 'item1'}}}},
        {'Get': {'TableName': t, 'Key': {'pk': {'SS': ['f', 'f']}}}},
    ]), 'TransactGetItems with a duplicate-bearing SS Get.Key beside a valid Get')
    assert code == ERR_VALIDATION, f'TransactGetItems with a duplicate SS key: got {code!r}'
    assert message == invalid + 'Input collection ["f", "f"] contains duplicates.', (
        f'TransactGetItems with a duplicate SS key: got message {message!r}'
    )

    # Neither the valid sibling Put nor any of the probed items landed: rejection is request-wide.
    scanned = ddb.scan(TableName=t, ConsistentRead=True)
    assert scanned['Items'] == [{'pk': {'S': 'item1'}, 'other': {'S': 'x'}}], (
        f'no write from a rejected ConditionExpression, Key or Transact*Items call may land, '
        f'including a valid sibling slot, got {scanned["Items"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
