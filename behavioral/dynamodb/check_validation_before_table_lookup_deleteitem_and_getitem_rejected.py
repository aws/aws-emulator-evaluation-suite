"""validation-before-table-lookup-deleteitem-and-getitem-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validation-before-table-lookup-deleteitem-and-getitem-rejected"
GROUP = 'negative-classes'
SERVICES = ['dynamodb']

_RETURN_VALUES_INVALID = (
    'ValidationException',
    '1 validation error detected: ReturnValues can only be ALL_OLD or NONE',
)
_CONSUMED_CAPACITY_INVALID = (
    'ValidationException',
    "1 validation error detected: Value 'INVALID_VALUE' at 'returnConsumedCapacity' failed to "
    "satisfy constraint: Member must satisfy enum value set: [INDEXES, TOTAL, NONE]",
)
_TABLE_NOT_FOUND = ('ResourceNotFoundException', 'Requested resource not found')


def expect_error(fn, code, message):
    """Assert *fn* raises exactly *code*/*message*; raise if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        got_code = exc.response.get('Error', {}).get('Code')
        got_message = exc.response.get('Error', {}).get('Message')
        assert got_code == code, f'expected {code}, got {got_code} (message {got_message!r})'
        assert got_message == message, f'expected message {message!r}, got {got_message!r}'
        return
    raise AssertionError(f'expected {code} to be refused, but the call SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """DeleteItem and GetItem validate their request before the table lookup: a malformed
    ReturnValues/ReturnConsumedCapacity fails ValidationException against a missing table, a
    well-formed one fails ResourceNotFoundException there, and both succeed on a table that exists.
    """
    ddb = ctx.client('dynamodb')
    ghost = ctx.unique_name('sim2real-behav-ghost-')
    key = {'pk': {'S': 'item'}}

    expect_error(
        lambda: ddb.delete_item(TableName=ghost, Key=key, ReturnValues='UPDATED_NEW'),
        *_RETURN_VALUES_INVALID,
    )
    expect_error(
        lambda: ddb.get_item(TableName=ghost, Key=key, ReturnConsumedCapacity='INVALID_VALUE'),
        *_CONSUMED_CAPACITY_INVALID,
    )

    expect_error(
        lambda: ddb.delete_item(TableName=ghost, Key=key, ReturnValues='ALL_OLD'),
        *_TABLE_NOT_FOUND,
    )
    expect_error(
        lambda: ddb.get_item(TableName=ghost, Key=key, ReturnConsumedCapacity='TOTAL'),
        *_TABLE_NOT_FOUND,
    )

    table = ctx.unique_name('sim2real-behav-table-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})

    item = {'pk': {'S': 'item'}, 'body': {'S': 'present'}}
    ddb.put_item(TableName=table, Item=item)

    got = ddb.get_item(TableName=table, Key=key, ReturnConsumedCapacity='TOTAL', ConsistentRead=True)
    assert got.get('Item') == item, f'expected the stored item {item!r}, got {got.get("Item")!r}'
    capacity = got.get('ConsumedCapacity')
    assert capacity == {'TableName': table, 'CapacityUnits': 1.0}, (
        f'expected ConsumedCapacity for a 1-unit strongly consistent read of the table, got {capacity!r}'
    )

    deleted = ddb.delete_item(TableName=table, Key=key, ReturnValues='ALL_OLD')
    assert deleted.get('Attributes') == item, (
        f'expected the accepted DeleteItem to return the removed item {item!r}, got '
        f'{deleted.get("Attributes")!r}'
    )
    after = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item')
    assert after is None, f'the item must be gone after the accepted delete, found {after!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
