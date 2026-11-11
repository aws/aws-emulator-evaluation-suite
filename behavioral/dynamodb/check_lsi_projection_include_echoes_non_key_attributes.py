"""lsi-projection-include-echoes-non-key-attributes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-projection-include-echoes-non-key-attributes"
GROUP = 'access_path'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """DescribeTable echoes INCLUDE projections with NonKeyAttributes on LSIs and GSIs, ALL and
    KEYS_ONLY carry none, and a strongly consistent query of the INCLUDE LSI returns the row
    without an attribute outside the list.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    projected = ['p1', 'p2', 'p3']
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'N'},
            {'AttributeName': 'li_inc', 'AttributeType': 'S'},
            {'AttributeName': 'li_all', 'AttributeType': 'S'},
            {'AttributeName': 'li_keys', 'AttributeType': 'S'},
            {'AttributeName': 'gi_inc', 'AttributeType': 'S'},
        ],
        LocalSecondaryIndexes=[
            {'IndexName': 'lsi_include',
             'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'li_inc', 'KeyType': 'RANGE'}],
             'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': projected}},
            {'IndexName': 'lsi_all',
             'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'li_all', 'KeyType': 'RANGE'}],
             'Projection': {'ProjectionType': 'ALL'}},
            {'IndexName': 'lsi_keys',
             'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'li_keys', 'KeyType': 'RANGE'}],
             'Projection': {'ProjectionType': 'KEYS_ONLY'}},
        ],
        GlobalSecondaryIndexes=[
            {'IndexName': 'gsi_include',
             'KeySchema': [{'AttributeName': 'gi_inc', 'KeyType': 'HASH'}],
             'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': projected}},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    desc = ddb.describe_table(TableName=t)['Table']
    lsis = {i['IndexName']: i for i in desc.get('LocalSecondaryIndexes') or []}
    gsis = {i['IndexName']: i for i in desc.get('GlobalSecondaryIndexes') or []}
    assert set(lsis) == {'lsi_include', 'lsi_all', 'lsi_keys'}, f'all three LSIs must be described, got {sorted(lsis)}'
    assert set(gsis) == {'gsi_include'}, f'the GSI must be described, got {sorted(gsis)}'

    for label, index in (('lsi_include', lsis.get('lsi_include')), ('gsi_include', gsis.get('gsi_include'))):
        proj = (index or {}).get('Projection') or {}
        assert proj.get('ProjectionType') == 'INCLUDE', (
            f'{label} must report ProjectionType=INCLUDE, got {proj.get("ProjectionType")!r}'
        )
        assert sorted(proj.get('NonKeyAttributes') or []) == sorted(projected), (
            f'{label} must echo the NonKeyAttributes it was created with '
            f'({projected}), got {proj.get("NonKeyAttributes")!r}'
        )

    for name, expected_type in (('lsi_all', 'ALL'), ('lsi_keys', 'KEYS_ONLY')):
        proj = lsis[name].get('Projection') or {}
        assert proj.get('ProjectionType') == expected_type, (
            f'{name} must report ProjectionType={expected_type}, got {proj.get("ProjectionType")!r}'
        )
        assert not proj.get('NonKeyAttributes'), (
            f'{name} projects {expected_type} and must NOT carry NonKeyAttributes, '
            f'got {proj.get("NonKeyAttributes")!r}'
        )

    # The projection governs reads, not only the description: an attribute outside
    # the INCLUDE list is absent from an index query even though it is on the item.
    ddb.put_item(TableName=t, Item={
        'pk': {'S': 'a'}, 'sk': {'N': '1'}, 'li_inc': {'S': 'x'},
        'p1': {'S': 'in'}, 'outside': {'S': 'out'},
    })
    rows = ddb.query(
        TableName=t, IndexName='lsi_include',
        KeyConditionExpression='pk = :p', ExpressionAttributeValues={':p': {'S': 'a'}},
        ConsistentRead=True,
    ).get('Items') or []
    assert len(rows) == 1, f'the INCLUDE index must return the one matching row, got {len(rows)}'
    assert rows[0].get('p1') == {'S': 'in'}, f'a projected attribute must be returned, got {rows[0].get("p1")!r}'
    assert 'outside' not in rows[0], (
        f'an attribute outside NonKeyAttributes must not be projected, got {rows[0].get("outside")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
