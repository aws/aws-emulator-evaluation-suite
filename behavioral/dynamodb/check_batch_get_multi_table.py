"""batch-get-multi-table."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-multi-table"
GROUP = 'batch'
SERVICES = ['dynamodb']


def _simple_table(ctx, ddb, prefix):
    name = ctx.unique_name(prefix)
    ddb.create_table(TableName=name, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda n=name: ddb.delete_table(TableName=n))
    ddb.get_waiter('table_exists').wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single BatchGetItem call spanning TWO different tables returns each table's matched items
    under its own key in the Responses map, correctly attributed and with no cross-table bleed.
    """
    ddb = ctx.client('dynamodb')
    table_a = _simple_table(ctx, ddb, 'sim2real-behav-bgi-a-')
    table_b = _simple_table(ctx, ddb, 'sim2real-behav-bgi-b-')

    ddb.put_item(TableName=table_a, Item={'pk': {'S': 'k1'}, 'from': {'S': 'a'}})
    ddb.put_item(TableName=table_a, Item={'pk': {'S': 'k2'}, 'from': {'S': 'a'}})
    ddb.put_item(TableName=table_b, Item={'pk': {'S': 'k1'}, 'from': {'S': 'b'}})

    resp = ddb.batch_get_item(
        RequestItems={
            table_a: {'Keys': [{'pk': {'S': 'k1'}}, {'pk': {'S': 'k2'}}], 'ConsistentRead': True},
            table_b: {'Keys': [{'pk': {'S': 'k1'}}, {'pk': {'S': 'missing'}}], 'ConsistentRead': True},
        }
    )
    responses = resp['Responses']
    pks_a = sorted(it['pk']['S'] for it in responses[table_a])
    assert pks_a == ['k1', 'k2'], f"table_a expected keys ['k1', 'k2'], got {pks_a}"
    assert all(it['from'] == {'S': 'a'} for it in responses[table_a]), responses[table_a]
    pks_b = sorted(it['pk']['S'] for it in responses[table_b])
    assert pks_b == ['k1'], f"table_b expected only ['k1'] ('missing' has no item), got {pks_b}"
    assert responses[table_b][0]['from'] == {'S': 'b'}, responses[table_b]
    assert resp.get('UnprocessedKeys', {}) == {}, resp.get('UnprocessedKeys')


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
