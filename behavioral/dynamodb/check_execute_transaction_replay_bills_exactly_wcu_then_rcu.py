"""execute-transaction-replay-bills-exactly-wcu-then-rcu."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "execute-transaction-replay-bills-exactly-wcu-then-rcu"
GROUP = 'partiql'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReturnConsumedCapacity=INDEXES on a 1-item ExecuteTransaction write reports an exact
    WriteCapacityUnits with no ReadCapacityUnits key; the same-token replay reports the
    mirrored ReadCapacityUnits with no WriteCapacityUnits key, and the item is applied once."""
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

    token = uuid.uuid4().hex
    key = {'S': 'et-bill-1'}
    statements = [
        {
            'Statement': f'INSERT INTO "{t}" VALUE {{\'pk\': ?, \'v\': ?}}',
            'Parameters': [key, {'N': '1'}],
        }
    ]

    first = ddb.execute_transaction(
        TransactStatements=statements, ClientRequestToken=token, ReturnConsumedCapacity='INDEXES')
    cc1 = first['ConsumedCapacity'][0]
    assert cc1.get('WriteCapacityUnits') == 2, (
        f'the first use of a fresh token on a 1-item write transaction must bill 2 WCU, got {cc1!r}'
    )
    assert 'ReadCapacityUnits' not in cc1, (
        f'a fresh-token write transaction must carry no ReadCapacityUnits key, got {cc1!r}'
    )
    item = ddb.get_item(TableName=t, Key={'pk': key}, ConsistentRead=True)['Item']
    assert item['v'] == {'N': '1'}, item

    replay = ddb.execute_transaction(
        TransactStatements=statements, ClientRequestToken=token, ReturnConsumedCapacity='INDEXES')
    cc2 = replay['ConsumedCapacity'][0]
    assert cc2.get('ReadCapacityUnits') == 2, (
        f'a deduplicated replay of a 1-item write transaction must bill 2 RCU, got {cc2!r}'
    )
    assert 'WriteCapacityUnits' not in cc2, (
        f'a deduplicated replay must carry no WriteCapacityUnits key, got {cc2!r}'
    )
    replayed_item = ddb.get_item(TableName=t, Key={'pk': key}, ConsistentRead=True)['Item']
    assert replayed_item['v'] == {'N': '1'}, 'deduplicated replay must not alter the item'

    scanned = ddb.scan(TableName=t, ConsistentRead=True)
    assert scanned['Count'] == 1, f'the item must be applied exactly once, scan reported {scanned["Count"]}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
