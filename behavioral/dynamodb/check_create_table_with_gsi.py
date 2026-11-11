"""create-table-with-gsi."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-table-with-gsi"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTable with a GSI returns the index in DescribeTable."""
    ddb = ctx.client('dynamodb')
    gsi = [{'IndexName': 'gsi-email', 'KeySchema': [{'AttributeName': 'email', 'KeyType': 'HASH'}], 'Projection': {'ProjectionType': 'ALL'}}]
    table = ctx.unique_name('sim2real-behav-')
    _ks = [{'AttributeName': 'pk', 'KeyType': 'HASH'}]
    _ad = [{'AttributeName': 'pk', 'AttributeType': 'S'}]
    for _ix in list(gsi):
        for _ke in _ix.get('KeySchema', []):
            if not any((_a['AttributeName'] == _ke['AttributeName'] for _a in _ad)):
                _ad.append({'AttributeName': _ke['AttributeName'], 'AttributeType': 'S'})
    _ctk = {'TableName': table, 'KeySchema': _ks, 'AttributeDefinitions': _ad, 'BillingMode': 'PAY_PER_REQUEST'}
    _ctk['GlobalSecondaryIndexes'] = gsi
    _ctk['Tags'] = [{'Key': 'sim2real-behav', 'Value': CHECK}]
    ddb.create_table(**_ctk)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    desc = ddb.describe_table(TableName=table)['Table']
    gsis = {g['IndexName']: g for g in desc.get('GlobalSecondaryIndexes', [])}
    assert set(gsis) == {'gsi-email'}, f"expected exactly ['gsi-email'], got {sorted(gsis)}"
    assert gsis['gsi-email']['IndexStatus'] == 'ACTIVE', f"expected ACTIVE, got {gsis['gsi-email']['IndexStatus']}"
    assert gsis['gsi-email']['Projection']['ProjectionType'] == 'ALL', f"expected ALL, got {gsis['gsi-email']['Projection']['ProjectionType']}"
    assert gsis['gsi-email']['KeySchema'] == [{'AttributeName': 'email', 'KeyType': 'HASH'}], f"unexpected KeySchema {gsis['gsi-email']['KeySchema']}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
