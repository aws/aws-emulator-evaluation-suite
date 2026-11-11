"""update-delete-last-set-element-removes-attribute."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-delete-last-set-element-removes-attribute"
GROUP = 'expressions'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error_code(fn):
    """Call fn(); return its ClientError code and message, raising on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DynamoDB has no empty set: DELETE of a set's last member removes the attribute, ADD re-creates
    it, DELETE of a non-member is a no-op, and writing an empty SS or NS is ValidationException.
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

    key = {'pk': {'S': 'sets'}}
    ddb.put_item(TableName=t, Item={**key, 'tags': {'SS': ['only']}, 'nums': {'NS': ['7']}, 'keep': {'S': 'k'}})

    # DELETE the last String Set member -> the ATTRIBUTE is gone, the item survives.
    ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='DELETE tags :rm',
        ExpressionAttributeValues={':rm': {'SS': ['only']}},
    )
    item = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert 'tags' not in item, (
        f'removing a set\'s final member must delete the attribute, not leave an empty set; got '
        f'tags={item.get("tags")}'
    )
    assert item['keep'] == {'S': 'k'}, f'the rest of the item must be untouched, got {item}'
    assert item['pk'] == {'S': 'sets'}, f'the key must survive, got {item}'

    # attribute_not_exists must now hold for that attribute -- the observable consequence.
    ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='SET marker = :m',
        ConditionExpression='attribute_not_exists(tags)',
        ExpressionAttributeValues={':m': {'S': 'gone'}},
    )

    # Same rule for a Number Set.
    ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='DELETE nums :rm',
        ExpressionAttributeValues={':rm': {'NS': ['7']}},
    )
    item = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert 'nums' not in item, (
        f'removing a Number Set\'s final member must delete the attribute; got nums={item.get("nums")}'
    )

    # ADD re-creates the attribute from nothing.
    ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='ADD tags :add',
        ExpressionAttributeValues={':add': {'SS': ['x', 'y']}},
    )
    item = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert set(item['tags']['SS']) == {'x', 'y'}, (
        f'ADD on a missing set attribute must create it with the added members, got {item.get("tags")}'
    )

    # DELETE of a non-member is a silent no-op (no error, set unchanged).
    ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='DELETE tags :rm',
        ExpressionAttributeValues={':rm': {'SS': ['not-a-member']}},
    )
    item = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert set(item['tags']['SS']) == {'x', 'y'}, (
        f'DELETE of a non-member must leave the set unchanged, got {item.get("tags")}'
    )

    # DELETE of every remaining member removes the attribute again.
    ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='DELETE tags :rm',
        ExpressionAttributeValues={':rm': {'SS': ['x', 'y']}},
    )
    item = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert 'tags' not in item, (
        f'deleting every member must remove the attribute, got tags={item.get("tags")}'
    )

    # The empty set is not a representable value: writing one directly is rejected, and the
    # rejected write leaves no item behind.
    code, message = _error_code(lambda: ddb.put_item(
        TableName=t, Item={'pk': {'S': 'empty-ss'}, 'tags': {'SS': []}},
    ))
    assert code == ERR_VALIDATION, (
        f'PutItem with an empty String Set must be rejected with {ERR_VALIDATION}; got {code}'
    )
    assert message == "1 validation error detected: One or more parameter values were invalid: An string set  may not be empty", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    leaked = ddb.get_item(TableName=t, Key={'pk': {'S': 'empty-ss'}}, ConsistentRead=True)
    assert 'Item' not in leaked, (
        f'the rejected empty-set PutItem must not create an item, found {leaked.get("Item")}'
    )
    ns_code, ns_message = _error_code(lambda: ddb.put_item(
        TableName=t, Item={'pk': {'S': 'empty-ns'}, 'nums': {'NS': []}},
    ))
    assert ns_code == ERR_VALIDATION, (
        f'PutItem with an empty Number Set must be rejected with {ERR_VALIDATION}; got {ns_code}'
    )
    assert ns_message == "1 validation error detected: One or more parameter values were invalid: An number set  may not be empty", (
        f"expected AWS's exact ValidationException message, got {ns_message!r}"
    )

    # Control: the same write with a non-empty set succeeds.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'empty-ss'}, 'tags': {'SS': ['ok']}})
    control = ddb.get_item(TableName=t, Key={'pk': {'S': 'empty-ss'}}, ConsistentRead=True)['Item']
    assert control['tags'] == {'SS': ['ok']}, f'control non-empty-set write must succeed, got {control}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
