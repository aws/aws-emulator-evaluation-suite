"""transact-write-items-per-item-all-old-opt-in-across-condition-failures."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-per-item-all-old-opt-in-across-condition-failures"
GROUP = 'transactions'
SERVICES = ['dynamodb']
ERR_TRANSACTION_CANCELED = 'TransactionCanceledException'
CONDITION_FAILED_MESSAGE = 'The conditional request failed'
CANCELED_PREFIX = 'Transaction cancelled, please refer cancellation reasons for specific reasons '


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Four condition-check failures in one TransactWriteItems each carry a reason positionally
    aligned with its TransactItems slot, with Item present only for the slots that set
    ReturnValuesOnConditionCheckFailure=ALL_OLD, independently of whether their neighbors opted in.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    item_a = {'pk': {'S': 'A'}, 'ver': {'N': '1'}, 'tag': {'S': 'alpha'}}
    item_b = {'pk': {'S': 'B'}, 'ver': {'N': '1'}, 'tag': {'S': 'bravo'}}
    item_c = {'pk': {'S': 'C'}, 'ver': {'N': '1'}, 'tag': {'S': 'charlie'}}
    item_d = {'pk': {'S': 'D'}, 'ver': {'N': '1'}, 'tag': {'S': 'delta'}}
    for item in (item_a, item_b, item_c, item_d):
        ddb.put_item(TableName=t, Item=item)

    # Slot 0 would succeed; slots 1-4 all fail their ConditionExpression, with ALL_OLD opted in on
    # slots 1 and 3 only (a ConditionCheck, an Update, a Delete and a Put, one action type each).
    try:
        ddb.transact_write_items(TransactItems=[
            {'Put': {'TableName': t, 'Item': {'pk': {'S': 'E'}, 'tag': {'S': 'echo'}}}},
            {'ConditionCheck': {
                'TableName': t,
                'Key': {'pk': {'S': 'A'}},
                'ConditionExpression': 'ver = :stale',
                'ExpressionAttributeValues': {':stale': {'N': '99'}},
                'ReturnValuesOnConditionCheckFailure': 'ALL_OLD',
            }},
            {'Update': {
                'TableName': t,
                'Key': {'pk': {'S': 'B'}},
                'UpdateExpression': 'SET tag = :new',
                'ConditionExpression': 'ver = :stale',
                'ExpressionAttributeValues': {':new': {'S': 'clobbered'}, ':stale': {'N': '99'}},
            }},
            {'Delete': {
                'TableName': t,
                'Key': {'pk': {'S': 'C'}},
                'ConditionExpression': 'ver = :stale',
                'ExpressionAttributeValues': {':stale': {'N': '99'}},
                'ReturnValuesOnConditionCheckFailure': 'ALL_OLD',
            }},
            {'Put': {
                'TableName': t,
                'Item': {'pk': {'S': 'D'}, 'ver': {'N': '2'}, 'tag': {'S': 'clobbered'}},
                'ConditionExpression': 'ver = :stale',
                'ExpressionAttributeValues': {':stale': {'N': '99'}},
            }},
        ])
        err = None
    except ClientError as exc:
        err = exc.response

    assert err is not None, 'four stale conditions must cancel the transaction'
    assert err['Error']['Code'] == ERR_TRANSACTION_CANCELED, (
        f'expected {ERR_TRANSACTION_CANCELED}, got {err["Error"].get("Code")}'
    )
    expected_message = CANCELED_PREFIX + (
        '[None, ConditionalCheckFailed, ConditionalCheckFailed, ConditionalCheckFailed, '
        'ConditionalCheckFailed]'
    )
    assert err['Error'].get('Message') == expected_message, (
        f'expected message {expected_message!r}, got {err["Error"].get("Message")!r}'
    )

    reasons = err.get('CancellationReasons')
    assert reasons is not None and len(reasons) == 5, (
        f'CancellationReasons must be positionally aligned with the 5 TransactItems, got {reasons}'
    )

    ok = reasons[0]
    assert ok['Code'] == 'None', f'slot 0 (not opted into ALL_OLD, not failing) must be "None", got {ok}'
    assert 'Item' not in ok, f'slot 0 must carry no Item, got {ok.get("Item")}'
    assert 'Message' not in ok, (
        f'slot 0 must carry no Message, got {ok.get("Message")}'
    )

    for slot, expected_item in ((1, item_a), (3, item_c)):
        reason = reasons[slot]
        assert reason['Code'] == 'ConditionalCheckFailed', (
            f'slot {slot} must report ConditionalCheckFailed, got {reason}'
        )
        assert reason.get('Message') == CONDITION_FAILED_MESSAGE, (
            f'slot {slot} must carry {CONDITION_FAILED_MESSAGE!r}, got {reason.get("Message")!r}'
        )
        assert reason.get('Item') == expected_item, (
            f'slot {slot} opted into ALL_OLD and must return {expected_item}, got {reason.get("Item")}'
        )

    for slot in (2, 4):
        reason = reasons[slot]
        assert reason['Code'] == 'ConditionalCheckFailed', (
            f'slot {slot} must report ConditionalCheckFailed, got {reason}'
        )
        assert reason.get('Message') == CONDITION_FAILED_MESSAGE, (
            f'slot {slot} must carry {CONDITION_FAILED_MESSAGE!r}, got {reason.get("Message")!r}'
        )
        assert 'Item' not in reason, (
            f'slot {slot} did not opt into ALL_OLD and must carry no Item, got {reason.get("Item")}'
        )

    # Effects absent: nothing the canceled transaction touched actually changed.
    assert 'Item' not in ddb.get_item(TableName=t, Key={'pk': {'S': 'E'}}, ConsistentRead=True), (
        'the transaction was canceled, so slot 0 must not have created item E'
    )
    for expected_item in (item_a, item_b, item_c, item_d):
        still = ddb.get_item(
            TableName=t, Key={'pk': expected_item['pk']}, ConsistentRead=True
        )['Item']
        assert still == expected_item, (
            f'{expected_item["pk"]} must be unchanged by the canceled transaction, got {still}'
        )

    # Positive control: the same item types, each condition now satisfied, commit together.
    ddb.transact_write_items(TransactItems=[
        {'Put': {'TableName': t, 'Item': {'pk': {'S': 'E'}, 'tag': {'S': 'echo'}}}},
        {'ConditionCheck': {
            'TableName': t,
            'Key': {'pk': {'S': 'A'}},
            'ConditionExpression': 'ver = :cur',
            'ExpressionAttributeValues': {':cur': {'N': '1'}},
        }},
        {'Update': {
            'TableName': t,
            'Key': {'pk': {'S': 'B'}},
            'UpdateExpression': 'SET tag = :new',
            'ConditionExpression': 'ver = :cur',
            'ExpressionAttributeValues': {':new': {'S': 'updated'}, ':cur': {'N': '1'}},
        }},
        {'Delete': {
            'TableName': t,
            'Key': {'pk': {'S': 'C'}},
            'ConditionExpression': 'ver = :cur',
            'ExpressionAttributeValues': {':cur': {'N': '1'}},
        }},
        {'Put': {
            'TableName': t,
            'Item': {'pk': {'S': 'D'}, 'ver': {'N': '2'}, 'tag': {'S': 'updated'}},
            'ConditionExpression': 'ver = :cur',
            'ExpressionAttributeValues': {':cur': {'N': '1'}},
        }},
    ])

    e_after = ddb.get_item(TableName=t, Key={'pk': {'S': 'E'}}, ConsistentRead=True)['Item']
    assert e_after == {'pk': {'S': 'E'}, 'tag': {'S': 'echo'}}, f'slot 0 must have committed, got {e_after}'
    a_after = ddb.get_item(TableName=t, Key={'pk': {'S': 'A'}}, ConsistentRead=True)['Item']
    assert a_after == item_a, f'a passing ConditionCheck must leave A unchanged, got {a_after}'
    b_after = ddb.get_item(TableName=t, Key={'pk': {'S': 'B'}}, ConsistentRead=True)['Item']
    assert b_after == {'pk': {'S': 'B'}, 'ver': {'N': '1'}, 'tag': {'S': 'updated'}}, (
        f'the Update must have committed, got {b_after}'
    )
    assert 'Item' not in ddb.get_item(TableName=t, Key={'pk': {'S': 'C'}}, ConsistentRead=True), (
        'the Delete must have committed'
    )
    d_after = ddb.get_item(TableName=t, Key={'pk': {'S': 'D'}}, ConsistentRead=True)['Item']
    assert d_after == {'pk': {'S': 'D'}, 'ver': {'N': '2'}, 'tag': {'S': 'updated'}}, (
        f'the Put must have committed, got {d_after}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
