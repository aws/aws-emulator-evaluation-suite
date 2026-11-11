"""attribute-names-are-case-sensitive."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attribute-names-are-case-sensitive"
GROUP = 'representation'
SERVICES = ['dynamodb']

ERR_CONDITION_FAILED = 'ConditionalCheckFailedException'
_ITEM = {
    'pk': {'S': 'case'},
    'body': {'S': 'lower'},
    'Body': {'S': 'title'},
    'BODY': {'S': 'upper'},
}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Attribute names differing only in case are distinct attributes: they coexist on one item,
    and a projection, an update and attribute_exists each resolve exactly the matching spelling.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-attrcase-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item=_ITEM)

    def _current():
        return ddb.get_item(
            TableName=table, Key={'pk': {'S': 'case'}}, ConsistentRead=True,
        )['Item']

    assert _current() == _ITEM, (
        f'three attribute names differing only in case are three attributes and must all survive '
        f'one write: expected {_ITEM!r}, got {_current()!r}'
    )

    # Projection and condition are separate lookups from the round-trip: a store can keep three
    # attributes yet still resolve an expression name case-insensitively.
    for name, expected in (('body', 'lower'), ('Body', 'title'), ('BODY', 'upper')):
        projected = ddb.get_item(
            TableName=table,
            Key={'pk': {'S': 'case'}},
            ProjectionExpression='#n',
            ExpressionAttributeNames={'#n': name},
            ConsistentRead=True,
        )['Item']
        assert projected == {name: {'S': expected}}, (
            f'a projection on {name!r} must return that attribute alone, got {projected!r}'
        )

    ddb.update_item(
        TableName=table,
        Key={'pk': {'S': 'case'}},
        UpdateExpression='SET #n = :v',
        ExpressionAttributeNames={'#n': 'Body'},
        ExpressionAttributeValues={':v': {'S': 'title-updated'}},
    )
    after = _current()
    assert after == dict(_ITEM, Body={'S': 'title-updated'}), (
        f'updating Body must leave body and BODY untouched: expected only Body to change, got '
        f'{after!r}'
    )

    ddb.put_item(
        TableName=table,
        Item={'pk': {'S': 'guarded'}, 'Marker': {'S': 'present'}},
    )
    try:
        ddb.update_item(
            TableName=table,
            Key={'pk': {'S': 'guarded'}},
            UpdateExpression='SET touched = :t',
            ExpressionAttributeValues={':t': {'BOOL': True}},
            ConditionExpression='attribute_exists(marker)',
        )
        raise AssertionError(
            'the item carries Marker, not marker, so attribute_exists(marker) must not match and '
            'the update must be refused; it SUCCEEDED'
        )
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        message = exc.response.get('Error', {}).get('Message')
        assert code == ERR_CONDITION_FAILED, (
            f'a condition on an attribute name whose case does not match must fail the condition, '
            f'not the request: expected {ERR_CONDITION_FAILED}, got {code}'
        )
        assert message == "The conditional request failed", (
            f"expected AWS's exact ConditionalCheckFailedException message, got {message!r}"
        )

    guarded = ddb.get_item(
        TableName=table, Key={'pk': {'S': 'guarded'}}, ConsistentRead=True,
    )['Item']
    assert 'touched' not in guarded, (
        f'the refused update must not have written its attribute, got {guarded!r}'
    )

    # Control: the same condition with the matching case succeeds.
    ddb.update_item(
        TableName=table,
        Key={'pk': {'S': 'guarded'}},
        UpdateExpression='SET touched = :t',
        ExpressionAttributeValues={':t': {'BOOL': True}},
        ConditionExpression='attribute_exists(Marker)',
    )
    guarded = ddb.get_item(
        TableName=table, Key={'pk': {'S': 'guarded'}}, ConsistentRead=True,
    )['Item']
    assert guarded.get('touched') == {'BOOL': True}, (
        f'the same condition spelled to match must succeed and apply the update, got {guarded!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
