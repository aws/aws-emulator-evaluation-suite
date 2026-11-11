"""update-item-key-attribute-immutable."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-key-attribute-immutable"
GROUP = 'item_crud'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error(fn):
    """The Error dict of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {})
    raise AssertionError(f'real AWS rejects this UpdateItem, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem MUST reject an UpdateExpression that attempts to SET a key attribute (the primary
    key is immutable post-creation) with ValidationException.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {'pk': {'S': 'immutable-key'}}
    ddb.put_item(TableName=t, Item={**key, 'v': {'S': '1'}})

    # Positive control: an ordinary (non-key) UpdateItem against this same item must succeed,
    # so the rejection below is specific to touching the key and not "every UpdateItem fails".
    ddb.update_item(
        TableName=t,
        Key=key,
        UpdateExpression='SET v = :v2',
        ExpressionAttributeValues={':v2': {'S': '2'}},
    )
    after_control = ddb.get_item(TableName=t, Key=key, ConsistentRead=True).get('Item')
    assert after_control is not None and after_control['v']['S'] == '2', (
        f'positive control: expected v=2 after a legitimate UpdateItem, got {after_control}'
    )

    err = _error(
        lambda: ddb.update_item(
            TableName=t,
            Key=key,
            UpdateExpression='SET pk = :newpk',
            ExpressionAttributeValues={':newpk': {'S': 'different-key'}},
        )
    )
    assert err.get('Code') == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {err}'
    expected = 'One or more parameter values were invalid: Cannot update attribute pk. This attribute is part of the key'
    assert err.get('Message') == expected, f'expected message {expected!r}, got {err.get("Message")!r}'

    unchanged = ddb.get_item(TableName=t, Key=key, ConsistentRead=True).get('Item')
    assert unchanged is not None, (
        'rejected key-attribute update must leave the item retrievable at its original key'
    )
    assert unchanged['v']['S'] == '2', (
        f"rejected key-attribute update must not mutate the item, got v={unchanged.get('v')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
