"""update-item-add-delete-empty-string-set-member-and-zero-length-binary-set-member."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-item-add-delete-empty-string-set-member-and-zero-length-binary-set-member"
GROUP = 'expressions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem ADD/DELETE on a String Set follow ordinary set semantics for the empty-string
    member, and ADD on a Binary Set accepts a zero-length member.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-ddb-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-behav', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})

    key = {'pk': {'S': 'sets'}}
    ddb.put_item(TableName=t, Item=dict(key))

    # ADD [''] onto an absent attribute creates an SS of just the empty string.
    item = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='ADD tags :e', ExpressionAttributeValues={':e': {'SS': ['']}},
        ReturnValues='ALL_NEW',
    )['Attributes']
    assert item['tags']['SS'] == [''], (
        f"ADD {{'SS': ['']}} onto an absent attribute produced {item.get('tags')!r}, expected {{'SS': ['']}}"
    )

    # ADD [''] again onto an SS that already holds only the empty string leaves one member.
    item = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='ADD tags :e', ExpressionAttributeValues={':e': {'SS': ['']}},
        ReturnValues='ALL_NEW',
    )['Attributes']
    assert item['tags']['SS'] == [''], (
        f"ADD {{'SS': ['']}} onto SS=[''] produced {item.get('tags')!r}, expected it to stay {{'SS': ['']}}"
    )

    # Bring in a second member so the set is {'', 'a'} (member order not asserted).
    item = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='ADD tags :e', ExpressionAttributeValues={':e': {'SS': ['a']}},
        ReturnValues='ALL_NEW',
    )['Attributes']
    assert set(item['tags']['SS']) == {'', 'a'}, (
        f"ADD {{'SS': ['a']}} onto SS=[''] produced {item.get('tags')!r}, expected the set {{'', 'a'}}"
    )

    # DELETE [''] from {'', 'a'} leaves just ['a'].
    item = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='DELETE tags :rm', ExpressionAttributeValues={':rm': {'SS': ['']}},
        ReturnValues='ALL_NEW',
    )['Attributes']
    assert item['tags']['SS'] == ['a'], (
        f"DELETE {{'SS': ['']}} from SS={{'', 'a'}} produced {item.get('tags')!r}, expected {{'SS': ['a']}}"
    )

    # Put the empty string back, so the set is {'', 'a'} again.
    item = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='ADD tags :e', ExpressionAttributeValues={':e': {'SS': ['']}},
        ReturnValues='ALL_NEW',
    )['Attributes']
    assert set(item['tags']['SS']) == {'', 'a'}, (
        f"ADD {{'SS': ['']}} onto SS=['a'] produced {item.get('tags')!r}, expected the set {{'', 'a'}}"
    )

    # DELETE ['a'] from {'', 'a'} leaves the SS holding only the empty string.
    item = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='DELETE tags :rm', ExpressionAttributeValues={':rm': {'SS': ['a']}},
        ReturnValues='ALL_NEW',
    )['Attributes']
    assert item['tags']['SS'] == [''], (
        f"DELETE {{'SS': ['a']}} from SS={{'', 'a'}} produced {item.get('tags')!r}, expected {{'SS': ['']}}"
    )

    # DELETE [''] from [''] removes the attribute entirely -- DynamoDB has no empty set.
    ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='DELETE tags :rm', ExpressionAttributeValues={':rm': {'SS': ['']}},
    )
    item = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)['Item']
    assert 'tags' not in item, (
        f"DELETE {{'SS': ['']}} from SS=[''] must remove the attribute, got tags={item.get('tags')!r}"
    )

    # ADD [b''] onto an absent Binary Set attribute creates one holding the zero-length member.
    item = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='ADD bins :e', ExpressionAttributeValues={':e': {'BS': [b'']}},
        ReturnValues='ALL_NEW',
    )['Attributes']
    assert item['bins']['BS'] == [b''], (
        f"ADD {{'BS': [b'']}} onto an absent attribute produced {item.get('bins')!r}, expected {{'BS': [b'']}}"
    )

    # ADD [b'x'] onto that Binary Set, then ADD [b''] again: the zero-length member joins it.
    ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='ADD bins :e', ExpressionAttributeValues={':e': {'BS': [b'x']}},
    )
    item = ddb.update_item(
        TableName=t, Key=key,
        UpdateExpression='ADD bins :e', ExpressionAttributeValues={':e': {'BS': [b'']}},
        ReturnValues='ALL_NEW',
    )['Attributes']
    assert set(item['bins']['BS']) == {b'', b'x'}, (
        f"ADD {{'BS': [b'']}} onto BS=[b'x'] produced {item.get('bins')!r}, expected the set {{b'', b'x'}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
