"""update-return-values-updated-old-and-new-scope."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-return-values-updated-old-and-new-scope"
GROUP = 'expressions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem ReturnValues differ in scope: UPDATED_NEW/UPDATED_OLD return only touched attributes,
    ALL_NEW/ALL_OLD the whole item with its key, NONE omits Attributes, and ALL_OLD on a new key
    omits Attributes rather than returning an empty map.
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

    key = {'pk': {'S': 'rv'}}
    ddb.put_item(TableName=t, Item={**key, 'a': {'N': '1'}, 'untouched': {'S': 'keep'}})

    # UPDATED_NEW: exactly the attributes SET by this expression, and nothing else.
    resp = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='SET a = :a, b = :b',
        ExpressionAttributeValues={':a': {'N': '2'}, ':b': {'S': 'new'}},
        ReturnValues='UPDATED_NEW',
    )
    attrs = resp['Attributes']
    assert attrs == {'a': {'N': '2'}, 'b': {'S': 'new'}}, (
        f'UPDATED_NEW must return exactly the updated attributes (no pk, no untouched), '
        f'got {attrs}'
    )
    assert 'pk' not in attrs, f'UPDATED_NEW must not echo the key, got {sorted(attrs)}'
    assert 'untouched' not in attrs, f'UPDATED_NEW must not echo untouched attributes, got {sorted(attrs)}'

    # UPDATED_OLD: the PRE-update values of exactly the touched attributes.
    resp = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='SET a = :a',
        ExpressionAttributeValues={':a': {'N': '3'}},
        ReturnValues='UPDATED_OLD',
    )
    attrs = resp['Attributes']
    assert attrs == {'a': {'N': '2'}}, (
        f'UPDATED_OLD must return only the pre-update value of the one touched attribute, got {attrs}'
    )

    # ALL_OLD: the ENTIRE prior item, key included.
    resp = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='SET a = :a',
        ExpressionAttributeValues={':a': {'N': '4'}},
        ReturnValues='ALL_OLD',
    )
    attrs = resp['Attributes']
    assert attrs == {'pk': {'S': 'rv'}, 'a': {'N': '3'}, 'b': {'S': 'new'}, 'untouched': {'S': 'keep'}}, (
        f'ALL_OLD must return the complete prior item including the key, got {attrs}'
    )

    # ALL_NEW: the ENTIRE resulting item, key included.
    resp = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='SET a = :a',
        ExpressionAttributeValues={':a': {'N': '5'}},
        ReturnValues='ALL_NEW',
    )
    attrs = resp['Attributes']
    assert attrs == {'pk': {'S': 'rv'}, 'a': {'N': '5'}, 'b': {'S': 'new'}, 'untouched': {'S': 'keep'}}, (
        f'ALL_NEW must return the complete resulting item including the key, got {attrs}'
    )

    # NONE: no Attributes member at all (not an empty map).
    resp = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='SET a = :a',
        ExpressionAttributeValues={':a': {'N': '6'}},
        ReturnValues='NONE',
    )
    assert 'Attributes' not in resp, (
        f'ReturnValues=NONE must omit Attributes entirely, got {resp.get("Attributes")}'
    )

    # ALL_OLD on an UpsertING update: the item is created, but there is no prior item, so
    # Attributes must be omitted rather than returned empty.
    fresh = {'pk': {'S': 'rv-fresh'}}
    resp = ddb.update_item(
        TableName=t, Key=fresh,
        UpdateExpression='SET c = :c',
        ExpressionAttributeValues={':c': {'S': 'created'}},
        ReturnValues='ALL_OLD',
    )
    assert 'Attributes' not in resp, (
        f'ALL_OLD on a key with no prior item must omit Attributes, got {resp.get("Attributes")}'
    )
    created = ddb.get_item(TableName=t, Key=fresh, ConsistentRead=True)['Item']
    assert created == {'pk': {'S': 'rv-fresh'}, 'c': {'S': 'created'}}, (
        f'the upserting UpdateItem must still have created the item, got {created}'
    )

    # UPDATED_OLD on that same brand-new key's next update returns only the touched attribute.
    resp = ddb.update_item(
        TableName=t, Key=fresh,
        UpdateExpression='SET c = :c',
        ExpressionAttributeValues={':c': {'S': 'replaced'}},
        ReturnValues='UPDATED_OLD',
    )
    assert resp['Attributes'] == {'c': {'S': 'created'}}, (
        f'UPDATED_OLD must return only the touched attribute, got {resp["Attributes"]}'
    )

    # Final state check: the sequence of updates landed exactly as expected.
    final = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert final == {'pk': {'S': 'rv'}, 'a': {'N': '6'}, 'b': {'S': 'new'}, 'untouched': {'S': 'keep'}}, (
        f'unexpected final item state, got {final}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
