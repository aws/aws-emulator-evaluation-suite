"""update-item-key-schema-mismatch."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-key-schema-mismatch"
GROUP = 'item_crud'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
KEY_MISMATCH = 'The provided key element does not match the schema'


def _error(fn):
    """The Error dict of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {})
    raise AssertionError(f'real AWS rejects this UpdateItem, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem against a table with a composite (hash+range) key schema, called with a Key that
    omits the range key entirely -- or that names an attribute not in the schema -- must be
    rejected with ValidationException, not treated as "close enough".
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    full_key = {'pk': {'S': 'schema-mismatch-1'}, 'sk': {'S': 'sort-1'}}
    ddb.put_item(TableName=t, Item={**full_key, 'v': {'S': 'orig'}})

    # Positive control: an UpdateItem using the *correct* composite key must actually take
    # effect -- otherwise a target that unconditionally rejects UpdateItem would pass the
    # negatives below for the wrong reason.
    ddb.update_item(
        TableName=t,
        Key=full_key,
        UpdateExpression='SET v = :v',
        ExpressionAttributeValues={':v': {'S': 'live'}},
    )
    live = ddb.get_item(TableName=t, Key=full_key, ConsistentRead=True)['Item']
    assert live['v']['S'] == 'live', f"positive control: expected update to take effect, got {live.get('v')}"

    # Missing the range key ("sk") entirely -- does not match the declared KeySchema.
    err = _error(
        lambda: ddb.update_item(
            TableName=t,
            Key={'pk': {'S': 'schema-mismatch-1'}},
            UpdateExpression='SET v = :v',
            ExpressionAttributeValues={':v': {'S': 'hacked'}},
        )
    )
    assert err.get('Code') == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {err}'
    assert err.get('Message') == KEY_MISMATCH, f'expected message {KEY_MISMATCH!r}, got {err.get("Message")!r}'

    # A key containing an attribute that isn't part of the schema must be rejected the same way.
    err2 = _error(
        lambda: ddb.update_item(
            TableName=t,
            Key={'pk': {'S': 'schema-mismatch-1'}, 'not_a_key_attr': {'S': 'z'}},
            UpdateExpression='SET v = :v',
            ExpressionAttributeValues={':v': {'S': 'hacked2'}},
        )
    )
    assert err2.get('Code') == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {err2}'
    assert err2.get('Message') == KEY_MISMATCH, f'expected message {KEY_MISMATCH!r}, got {err2.get("Message")!r}'

    unchanged = ddb.get_item(TableName=t, Key=full_key, ConsistentRead=True)['Item']
    assert unchanged['v']['S'] == 'live', 'a rejected mismatched-key update must not mutate the real item'

    # The same mismatch, reached through BatchWriteItem: a PutRequest whose Item carries the
    # range key under the wrong scalar type (N where the schema declares S) is a key-schema
    # mismatch too, not a type-coercion opportunity.
    err3 = _error(
        lambda: ddb.batch_write_item(
            RequestItems={
                t: [
                    {
                        'PutRequest': {
                            'Item': {'pk': {'S': 'schema-mismatch-1'}, 'sk': {'N': '1'}, 'v': {'S': 'hacked3'}}
                        }
                    }
                ]
            }
        )
    )
    assert err3.get('Code') == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {err3}'
    assert err3.get('Message') == KEY_MISMATCH, f'expected message {KEY_MISMATCH!r}, got {err3.get("Message")!r}'

    still_unchanged = ddb.get_item(TableName=t, Key=full_key, ConsistentRead=True)['Item']
    assert still_unchanged['v']['S'] == 'live', (
        'a rejected BatchWriteItem key-type mismatch must not mutate the real item'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
