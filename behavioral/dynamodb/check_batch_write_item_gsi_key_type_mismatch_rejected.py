"""batch-write-item-gsi-key-type-mismatch-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-write-item-gsi-key-type-mismatch-rejected"
GROUP = 'access_path'
SERVICES = ['dynamodb']


def _error_code(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """BatchWriteItem carrying an index key whose type contradicts the index AttributeDefinition is
    refused, and the message names the index. Accepting it corrupts the index silently."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gpk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'N'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsi1',
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(
        TableName=table,
        WaiterConfig={'Delay': 1, 'MaxAttempts': max(10, int(ctx.time_left() or 300))},
    )
    err = _error_code(
        lambda: ddb.batch_write_item(RequestItems={table: [
            {'PutRequest': {'Item': {'pk': {'S': 'b'}, 'sk': {'S': '1'}, 'gpk': {'N': '9'}}}}]}),
        'a BatchWriteItem whose GSI key has the wrong type',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected_msg = ('One or more parameter values were invalid: Type mismatch for Index Key gpk '
                    'Expected: S Actual: N IndexName: gsi1')
    assert err.get('Message') == expected_msg, (
        f'the message must name the offending index key: expected {expected_msg!r}, got {err.get("Message")!r}'
    )
    assert ddb.scan(TableName=table, ConsistentRead=True)['Count'] == 0, (
        'the refused write must leave the table empty'
    )
    err_both = _error_code(
        lambda: ddb.batch_write_item(RequestItems={table: [
            {'PutRequest': {'Item': {
                'pk': {'S': 'b'}, 'sk': {'S': '2'}, 'gpk': {'N': '9'}, 'lsk': {'S': 'x'}}}}]}),
        'a BatchWriteItem whose LSI key and GSI key both have the wrong type',
    )
    assert err_both.get('Code') == 'ValidationException', (
        f"expected ValidationException, got {err_both.get('Code')}"
    )
    expected_both = ('One or more parameter values were invalid: Type mismatch for Index Key gpk '
                      'Expected: S Actual: N IndexName: gsi1')
    assert err_both.get('Message') == expected_both, (
        f'the message must name the offending index key: expected {expected_both!r}, got {err_both.get("Message")!r}'
    )
    assert ddb.scan(TableName=table, ConsistentRead=True)['Count'] == 0, (
        'the refused write must leave the table empty'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
