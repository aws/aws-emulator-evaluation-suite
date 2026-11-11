"""create-table-with-lsi."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-table-with-lsi"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTable with an LSI on a base table that has a sort key is described back with
    the LSI's own KeySchema and Projection, not merely echoed by name.
    """
    ddb = ctx.client('dynamodb')
    lsi = [{'IndexName': 'lsi-created', 'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'created_at', 'KeyType': 'RANGE'}], 'Projection': {'ProjectionType': 'ALL'}}]
    table = ctx.unique_name('sim2real-behav-')
    _ks = [{'AttributeName': 'pk', 'KeyType': 'HASH'}]
    _ad = [{'AttributeName': 'pk', 'AttributeType': 'S'}]
    _ks.append({'AttributeName': 'sk', 'KeyType': 'RANGE'})
    _ad.append({'AttributeName': 'sk', 'AttributeType': 'S'})
    for _ix in list(lsi):
        for _ke in _ix.get('KeySchema', []):
            if not any((_a['AttributeName'] == _ke['AttributeName'] for _a in _ad)):
                _ad.append({'AttributeName': _ke['AttributeName'], 'AttributeType': 'S'})
    _ctk = {'TableName': table, 'KeySchema': _ks, 'AttributeDefinitions': _ad, 'BillingMode': 'PAY_PER_REQUEST'}
    _ctk['LocalSecondaryIndexes'] = lsi
    ddb.create_table(**_ctk)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    desc = ddb.describe_table(TableName=table)['Table']
    lsis = {idx['IndexName']: idx for idx in desc.get('LocalSecondaryIndexes', [])}
    assert 'lsi-created' in lsis, f'expected lsi-created in {sorted(lsis)}'
    described = lsis['lsi-created']
    assert described['KeySchema'] == lsi[0]['KeySchema'], (
        f"expected KeySchema {lsi[0]['KeySchema']}, got {described['KeySchema']}"
    )
    assert described['Projection']['ProjectionType'] == 'ALL', (
        f"expected ProjectionType ALL, got {described['Projection']['ProjectionType']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
