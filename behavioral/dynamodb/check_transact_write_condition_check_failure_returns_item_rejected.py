"""transact-write-condition-check-failure-returns-item-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-condition-check-failure-returns-item-rejected"
GROUP = 'transactions'
SERVICES = ['dynamodb']
ERR_TRANSACTION_CANCELED = 'TransactionCanceledException'
CONDITION_FAILED_MESSAGE = 'The conditional request failed'
CANCELED_PREFIX = 'Transaction cancelled, please refer cancellation reasons for specific reasons '


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With ReturnValuesOnConditionCheckFailure=ALL_OLD only the failing member's reason carries the
    conflicting Item and a Message; the passing member reports Code='None' with neither, nothing is
    written, and without the opt-in no Item is returned.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': 'transact-write-condition-check-failure'}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    existing = {'pk': {'S': 'A'}, 'version': {'N': '1'}, 'payload': {'S': 'original'}}
    ddb.put_item(TableName=t, Item=existing)

    # Member 0 would succeed; member 1's optimistic-lock condition is stale and fails.
    try:
        ddb.transact_write_items(TransactItems=[
            {'Put': {'TableName': t, 'Item': {'pk': {'S': 'C'}, 'payload': {'S': 'never'}}}},
            {'Put': {
                'TableName': t,
                'Item': {'pk': {'S': 'A'}, 'version': {'N': '2'}, 'payload': {'S': 'clobbered'}},
                'ConditionExpression': 'version = :stale',
                'ExpressionAttributeValues': {':stale': {'N': '99'}},
                'ReturnValuesOnConditionCheckFailure': 'ALL_OLD',
            }},
        ])
        err = None
    except ClientError as exc:
        err = exc.response

    assert err is not None, 'a stale optimistic-lock condition must cancel the transaction'
    assert err['Error']['Code'] == ERR_TRANSACTION_CANCELED, (
        f'expected {ERR_TRANSACTION_CANCELED}, got {err["Error"].get("Code")}'
    )
    expected = CANCELED_PREFIX + '[None, ConditionalCheckFailed]'
    assert err['Error'].get('Message') == expected, (
        f'expected message {expected!r}, got {err["Error"].get("Message")!r}'
    )

    reasons = err.get('CancellationReasons')
    assert reasons is not None and len(reasons) == 2, (
        f'CancellationReasons must be positionally aligned with the 2 TransactItems, got {reasons}'
    )

    ok, failed = reasons[0], reasons[1]
    assert ok['Code'] == 'None', f'the non-failing member must report Code "None", got {ok}'
    assert 'Item' not in ok or ok.get('Item') is None, (
        f'the non-failing member must NOT carry an Item, got {ok.get("Item")}'
    )
    assert 'Message' not in ok or ok.get('Message') is None, (
        f'the non-failing member must NOT carry a Message, got {ok.get("Message")}'
    )

    assert failed['Code'] == 'ConditionalCheckFailed', (
        f'the failing member must report ConditionalCheckFailed, got {failed}'
    )
    assert failed.get('Message') == CONDITION_FAILED_MESSAGE, (
        f'the failing member must carry {CONDITION_FAILED_MESSAGE!r}, got {failed.get("Message")!r}'
    )
    assert failed.get('Item') == existing, (
        f'ReturnValuesOnConditionCheckFailure=ALL_OLD must return the COMPLETE conflicting item '
        f'{existing}, got {failed.get("Item")}'
    )

    # Effect absent: the would-have-succeeded member wrote nothing.
    assert 'Item' not in ddb.get_item(TableName=t, Key={'pk': {'S': 'C'}}, ConsistentRead=True), (
        'the transaction was canceled, so member 0 must not have created item C'
    )
    # And the conflicting item is byte-for-byte unchanged.
    still = ddb.get_item(TableName=t, Key={'pk': {'S': 'A'}}, ConsistentRead=True)['Item']
    assert still == existing, f'item A must be unchanged by the canceled transaction, got {still}'

    # Without ReturnValuesOnConditionCheckFailure the reason must carry NO Item -- the caller
    # opts in; the emulator must not volunteer it.
    try:
        ddb.transact_write_items(TransactItems=[
            {'Put': {
                'TableName': t,
                'Item': {'pk': {'S': 'A'}, 'version': {'N': '3'}},
                'ConditionExpression': 'version = :stale',
                'ExpressionAttributeValues': {':stale': {'N': '99'}},
            }},
        ])
        opt_out = None
    except ClientError as exc:
        opt_out = exc.response
    assert opt_out is not None and opt_out['Error']['Code'] == ERR_TRANSACTION_CANCELED, opt_out
    expected = CANCELED_PREFIX + '[ConditionalCheckFailed]'
    assert opt_out['Error'].get('Message') == expected, (
        f'expected message {expected!r}, got {opt_out["Error"].get("Message")!r}'
    )
    silent = opt_out['CancellationReasons'][0]
    assert silent['Code'] == 'ConditionalCheckFailed', silent
    assert silent.get('Message') == CONDITION_FAILED_MESSAGE, (
        f'the failing member must carry {CONDITION_FAILED_MESSAGE!r}, got {silent.get("Message")!r}'
    )
    assert 'Item' not in silent or silent.get('Item') is None, (
        f'without ReturnValuesOnConditionCheckFailure the reason must omit Item, got {silent.get("Item")}'
    )

    # Control: the same transaction with a satisfiable condition commits both members.
    ddb.transact_write_items(TransactItems=[
        {'Put': {'TableName': t, 'Item': {'pk': {'S': 'C'}, 'payload': {'S': 'committed'}}}},
        {'Put': {
            'TableName': t,
            'Item': {'pk': {'S': 'A'}, 'version': {'N': '2'}, 'payload': {'S': 'updated'}},
            'ConditionExpression': 'version = :cur',
            'ExpressionAttributeValues': {':cur': {'N': '1'}},
            'ReturnValuesOnConditionCheckFailure': 'ALL_OLD',
        }},
    ])
    c_after = ddb.get_item(TableName=t, Key={'pk': {'S': 'C'}}, ConsistentRead=True)['Item']
    assert c_after == {'pk': {'S': 'C'}, 'payload': {'S': 'committed'}}, (
        f'a transaction with a satisfiable condition must commit member 0, got {c_after}'
    )
    a_after = ddb.get_item(TableName=t, Key={'pk': {'S': 'A'}}, ConsistentRead=True)['Item']
    assert a_after == {'pk': {'S': 'A'}, 'version': {'N': '2'}, 'payload': {'S': 'updated'}}, (
        f'a transaction with a satisfiable condition must commit member 1, got {a_after}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
