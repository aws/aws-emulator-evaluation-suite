"""transact-write-cancellation-omits-capacity-and-collection-metrics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-cancellation-omits-capacity-and-collection-metrics"
GROUP = 'transactions'
SERVICES = ['dynamodb']
_CANCELED = (
    'TransactionCanceledException',
    'Transaction cancelled, please refer cancellation reasons for specific reasons '
    '[ConditionalCheckFailed, None]',
)


def expect_error(fn, code, message):
    """Calls ``fn``, asserts it raises ``(code, message)`` and returns the response for
    inspection; raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        got_code = exc.response['Error']['Code']
        got_message = exc.response['Error'].get('Message')
        assert got_code == code, f'expected error code {code!r}, got {got_code!r}'
        assert got_message == message, f'expected message {message!r}, got {got_message!r}'
        return exc.response
    raise AssertionError(f'expected {code} ({message!r}), but the call succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems canceled by a failing ConditionCheck returns the ALL_OLD conflicting
    item, but the error omits ConsumedCapacity and ItemCollectionMetrics even though both were
    requested; a committed transaction on the same LSI-bearing table reports both.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'alt', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
        LocalSecondaryIndexes=[{
            'IndexName': 'alt-index',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'alt', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    existing = {
        'pk': {'S': 'conflict'}, 'sk': {'S': 'v1'}, 'alt': {'S': 'a1'},
        'version': {'N': '1'}, 'payload': {'S': 'original'},
    }
    ddb.put_item(TableName=table, Item=existing)

    response = expect_error(
        lambda: ddb.transact_write_items(
            ReturnConsumedCapacity='INDEXES',
            ReturnItemCollectionMetrics='SIZE',
            TransactItems=[
                {'ConditionCheck': {
                    'TableName': table,
                    'Key': {'pk': {'S': 'conflict'}, 'sk': {'S': 'v1'}},
                    'ConditionExpression': 'version = :stale',
                    'ExpressionAttributeValues': {':stale': {'N': '99'}},
                    'ReturnValuesOnConditionCheckFailure': 'ALL_OLD',
                }},
                {'Put': {
                    'TableName': table,
                    'Item': {'pk': {'S': 'other'}, 'sk': {'S': 'v1'}, 'alt': {'S': 'a2'}},
                }},
            ],
        ),
        *_CANCELED,
    )

    reasons = response.get('CancellationReasons')
    assert reasons is not None and len(reasons) == 2, (
        f'CancellationReasons must be positionally aligned with the 2 TransactItems, got {reasons!r}'
    )
    failed, ok = reasons[0], reasons[1]
    assert failed['Code'] == 'ConditionalCheckFailed', (
        f'member 0 must report ConditionalCheckFailed, got {failed!r}'
    )
    assert failed.get('Message') == 'The conditional request failed', (
        f'member 0 must carry "The conditional request failed", got {failed.get("Message")!r}'
    )
    assert failed.get('Item') == existing, (
        f'ReturnValuesOnConditionCheckFailure=ALL_OLD must return the complete conflicting item '
        f'{existing!r}, got {failed.get("Item")!r}'
    )
    assert ok['Code'] == 'None', f'member 1 (not failing) must report Code "None", got {ok!r}'
    assert 'Item' not in ok, f'member 1 must not carry an Item, got {ok.get("Item")!r}'
    assert 'Message' not in ok, f'member 1 must not carry a Message, got {ok.get("Message")!r}'

    assert 'ConsumedCapacity' not in response, (
        f'a canceled TransactWriteItems error must omit ConsumedCapacity even when '
        f'ReturnConsumedCapacity=INDEXES was requested, got {response.get("ConsumedCapacity")!r}'
    )
    assert 'ItemCollectionMetrics' not in response, (
        f'a canceled TransactWriteItems error must omit ItemCollectionMetrics even when '
        f'ReturnItemCollectionMetrics=SIZE was requested, got {response.get("ItemCollectionMetrics")!r}'
    )

    unchanged = ddb.get_item(
        TableName=table, Key={'pk': {'S': 'conflict'}, 'sk': {'S': 'v1'}}, ConsistentRead=True
    )['Item']
    assert unchanged == existing, (
        f'the conflicting item is {unchanged!r} after a canceled transaction, expected it unchanged at {existing!r}'
    )
    assert 'Item' not in ddb.get_item(
        TableName=table, Key={'pk': {'S': 'other'}, 'sk': {'S': 'v1'}}, ConsistentRead=True
    ), 'the transaction was canceled, so the would-have-succeeded Put must not have written its item'

    # --- positive control: same table, a committing transaction with the same opt-ins set ---
    committed = ddb.transact_write_items(
        ReturnConsumedCapacity='INDEXES',
        ReturnItemCollectionMetrics='SIZE',
        TransactItems=[{'Put': {
            'TableName': table,
            'Item': {'pk': {'S': 'free'}, 'sk': {'S': 'v1'}, 'alt': {'S': 'a3'}},
        }}],
    )
    consumed = committed['ConsumedCapacity'][0]
    assert consumed.get('TableName') == table, f'ConsumedCapacity must name the written table, got {consumed!r}'
    assert consumed.get('WriteCapacityUnits') == 3.0, (
        f'a committed TransactWriteItems Put projected into one LSI reported WriteCapacityUnits '
        f'{consumed.get("WriteCapacityUnits")!r}, expected 3.0'
    )

    metrics = committed['ItemCollectionMetrics'][table]
    assert len(metrics) == 1, (
        f'a committed Put on an LSI-bearing table must report one ItemCollectionMetrics entry, got {metrics!r}'
    )
    key = metrics[0].get('ItemCollectionKey')
    assert key == {'pk': {'S': 'free'}}, (
        f'ItemCollectionKey must carry the partition key value of the written item, got {key!r}'
    )
    size_range = metrics[0].get('SizeEstimateRangeGB')
    assert size_range == [0.0, 1.0], (
        f'SizeEstimateRangeGB for a one-item collection must be [0.0, 1.0], got {size_range!r}'
    )

    assert ddb.get_item(
        TableName=table, Key={'pk': {'S': 'free'}, 'sk': {'S': 'v1'}}, ConsistentRead=True
    )['Item'] == {'pk': {'S': 'free'}, 'sk': {'S': 'v1'}, 'alt': {'S': 'a3'}}, (
        'the positive control item was not committed as written'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
