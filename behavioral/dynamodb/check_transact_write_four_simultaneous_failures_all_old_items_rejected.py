"""transact-write-four-simultaneous-failures-all-old-items-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'transact-write-four-simultaneous-failures-all-old-items-rejected'
GROUP = 'transactions'
SERVICES = ['dynamodb']
ERR_CANCELED = 'TransactionCanceledException'
COND_FAILED_MESSAGE = 'The conditional request failed'
CANCELED_PREFIX = 'Transaction cancelled, please refer cancellation reasons for specific reasons '


def _canceled(fn):
    """The err response of the ClientError ``fn`` raises; raises if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f'expected the transaction to be canceled, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems with one failing ConditionCheck, Put, Update and Delete reports four
    ConditionalCheckFailed reasons in request order; ALL_OLD on each preserves maps, lists and
    sets in full, and ALL_OLD on a Delete whose target never existed carries no Item.

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
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    cc_item = {
        'pk': {'S': 'cc-target'},
        'status': {'S': 'LOCKED'},
        'attrs': {'M': {'owner': {'S': 'ops'}, 'retries': {'N': '3'}}},
    }
    put_item = {
        'pk': {'S': 'put-target'},
        'tags': {'L': [{'S': 'a'}, {'S': 'b'}, {'N': '7'}]},
    }
    update_item = {
        'pk': {'S': 'update-target'},
        'version': {'N': '41'},
        'owners': {'SS': ['alice', 'bob']},
    }
    delete_key = {'pk': {'S': 'delete-target-never-created'}}
    ddb.put_item(TableName=table, Item=cc_item)
    ddb.put_item(TableName=table, Item=put_item)
    ddb.put_item(TableName=table, Item=update_item)

    def attempt(*, cc_expected, put_condition, update_expected_version, delete_key_present):
        return ddb.transact_write_items(TransactItems=[
            {'ConditionCheck': {
                'TableName': table, 'Key': {'pk': cc_item['pk']},
                'ConditionExpression': '#s = :expected',
                'ExpressionAttributeNames': {'#s': 'status'},
                'ExpressionAttributeValues': {':expected': {'S': cc_expected}},
                'ReturnValuesOnConditionCheckFailure': 'ALL_OLD',
            }},
            {'Put': {
                'TableName': table,
                'Item': {'pk': put_item['pk'], 'tags': {'L': [{'S': 'replaced'}]}},
                'ConditionExpression': put_condition,
                'ReturnValuesOnConditionCheckFailure': 'ALL_OLD',
            }},
            {'Update': {
                'TableName': table, 'Key': {'pk': update_item['pk']},
                'UpdateExpression': 'SET version = version + :one',
                'ConditionExpression': 'version = :v',
                'ExpressionAttributeValues': {
                    ':one': {'N': '1'}, ':v': {'N': str(update_expected_version)},
                },
                'ReturnValuesOnConditionCheckFailure': 'ALL_OLD',
            }},
            {'Delete': {
                'TableName': table, 'Key': delete_key,
                'ConditionExpression': 'attribute_exists(pk)' if delete_key_present
                                       else 'attribute_not_exists(pk)',
                'ReturnValuesOnConditionCheckFailure': 'ALL_OLD',
            }},
        ])

    # All four fail simultaneously: the ConditionCheck expects the wrong status, the Put's
    # attribute_not_exists is false because put-target already exists, the Update's version
    # guard is stale, and the Delete's attribute_exists is false because its target never
    # existed.
    err = _canceled(lambda: attempt(
        cc_expected='UNLOCKED', put_condition='attribute_not_exists(pk)',
        update_expected_version=99, delete_key_present=True,
    ))
    assert err['Error']['Code'] == ERR_CANCELED, (
        f"expected {ERR_CANCELED}, got {err['Error'].get('Code')!r}"
    )
    expected_message = CANCELED_PREFIX + (
        '[ConditionalCheckFailed, ConditionalCheckFailed, '
        'ConditionalCheckFailed, ConditionalCheckFailed]'
    )
    assert err['Error'].get('Message') == expected_message, (
        f"expected message {expected_message!r}, got {err['Error'].get('Message')!r}"
    )
    reasons = err.get('CancellationReasons')
    assert reasons is not None and len(reasons) == 4, (
        f'CancellationReasons must be positionally aligned with the 4 TransactItems, got {reasons}'
    )
    cc_reason, put_reason, update_reason, delete_reason = reasons

    assert cc_reason['Code'] == 'ConditionalCheckFailed', (
        f'member 0 (ConditionCheck) must report ConditionalCheckFailed, got {cc_reason}'
    )
    assert cc_reason.get('Message') == COND_FAILED_MESSAGE, cc_reason
    assert cc_reason.get('Item') == cc_item, (
        f'ALL_OLD on the ConditionCheck must return the complete item including its map, '
        f'got {cc_reason.get("Item")}'
    )

    assert put_reason['Code'] == 'ConditionalCheckFailed', (
        f'member 1 (Put) must report ConditionalCheckFailed, got {put_reason}'
    )
    assert put_reason.get('Message') == COND_FAILED_MESSAGE, put_reason
    assert put_reason.get('Item') == put_item, (
        f'ALL_OLD on the Put must return the complete conflicting item including its list, '
        f'got {put_reason.get("Item")}'
    )

    assert update_reason['Code'] == 'ConditionalCheckFailed', (
        f'member 2 (Update) must report ConditionalCheckFailed, got {update_reason}'
    )
    assert update_reason.get('Message') == COND_FAILED_MESSAGE, update_reason
    assert update_reason.get('Item') == update_item, (
        f'ALL_OLD on the Update must return the complete item including its string set, '
        f'got {update_reason.get("Item")}'
    )

    assert delete_reason['Code'] == 'ConditionalCheckFailed', (
        f'member 3 (Delete) must report ConditionalCheckFailed, got {delete_reason}'
    )
    assert delete_reason.get('Message') == COND_FAILED_MESSAGE, delete_reason
    assert 'Item' not in delete_reason, (
        f'ALL_OLD on a Delete whose target never existed must carry no Item, '
        f'got {delete_reason.get("Item")}'
    )

    # Effect absent: every item is byte-for-byte unchanged, and the never-created target stays absent.
    assert ddb.get_item(TableName=table, Key={'pk': cc_item['pk']}, ConsistentRead=True)['Item'] == cc_item
    assert ddb.get_item(TableName=table, Key={'pk': put_item['pk']}, ConsistentRead=True)['Item'] == put_item
    assert ddb.get_item(TableName=table, Key={'pk': update_item['pk']}, ConsistentRead=True)['Item'] == update_item
    assert 'Item' not in ddb.get_item(TableName=table, Key=delete_key, ConsistentRead=True), (
        'the canceled transaction must not have created the delete target'
    )

    # Positive control: the same four action kinds, all satisfiable, commit together.
    attempt(
        cc_expected='LOCKED', put_condition='attribute_exists(pk)',
        update_expected_version=41, delete_key_present=False,
    )
    assert ddb.get_item(TableName=table, Key={'pk': put_item['pk']}, ConsistentRead=True)['Item'] == {
        'pk': put_item['pk'], 'tags': {'L': [{'S': 'replaced'}]},
    }
    updated = ddb.get_item(TableName=table, Key={'pk': update_item['pk']}, ConsistentRead=True)['Item']
    assert updated == {**update_item, 'version': {'N': '42'}}, (
        f'a committed transaction must bump the version, got {updated}'
    )
    deleted = ddb.get_item(TableName=table, Key=delete_key, ConsistentRead=True)
    assert 'Item' not in deleted, (
        f'a committed Delete on a still-absent target leaves it absent, got {deleted}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
