"""update-item-set-ss-sole-empty-string-member-top-and-nested."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-item-set-ss-sole-empty-string-member-top-and-nested"
GROUP = 'representation'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:representation", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem SET of a string set whose only member is the empty string stores it,
    both as a top-level attribute and at a nested document path.
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

    ddb.put_item(TableName=t, Item={'pk': {'S': 'x'}, 'wrapper': {'M': {}}})

    updated = ddb.update_item(
        TableName=t, Key={'pk': {'S': 'x'}},
        UpdateExpression='SET #tg = :e, #w.#tg = :e',
        ExpressionAttributeNames={'#tg': 'tags', '#w': 'wrapper'},
        ExpressionAttributeValues={':e': {'SS': ['']}},
        ReturnValues='ALL_NEW',
    )['Attributes']
    assert updated.get('tags') == {'SS': ['']}, (
        f"SET #tg = :e with :e={{'SS': ['']}} must store the set at the top level, "
        f"got {updated.get('tags')!r}"
    )
    assert updated.get('wrapper', {}).get('M', {}).get('tags') == {'SS': ['']}, (
        f"SET #w.#tg = :e with :e={{'SS': ['']}} must store the set at the nested path, "
        f"got {updated.get('wrapper')!r}"
    )

    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'x'}}, ConsistentRead=True).get('Item', {})
    assert got.get('tags') == {'SS': ['']}, (
        f"a later GetItem must read back the top-level set as {{'SS': ['']}}, got {got.get('tags')!r}"
    )
    assert got.get('wrapper', {}).get('M', {}).get('tags') == {'SS': ['']}, (
        f"a later GetItem must read back the nested set as {{'SS': ['']}}, "
        f"got {got.get('wrapper')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
