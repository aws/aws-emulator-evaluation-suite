"""include-projection-governs-index-reads-on-lsi-and-gsi."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "include-projection-governs-index-reads-on-lsi-and-gsi"
GROUP = 'gsi'
SERVICES = ['dynamodb']

_LSI_INCLUDE = 'lsi-include'
_LSI_ALL = 'lsi-all'
_GSI_INCLUDE = 'gsi-include'
_GSI_KEYS_ONLY = 'gsi-keys-only'


def _poll(fn, pred, *, timeout_s, interval_s=2.0, description='condition'):
    """Poll `fn` until `pred` holds. A global secondary index is eventually consistent, so this
    waits for an observable condition rather than sleeping a fixed amount."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f'{description} not met within {timeout_s}s. Last: {value!r}')
        time.sleep(interval_s)
        value = fn()
    return value


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeTable echoes INCLUDE projections with NonKeyAttributes (none for ALL/KEYS_ONLY), and
    INCLUDE LSI/GSI queries return only keys plus the included attribute, while the ALL LSI returns
    the excluded one and the KEYS_ONLY GSI returns keys only."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-proj-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': n, 'AttributeType': 'S'}
                              for n in ('pk', 'sk', 'li', 'la', 'gi', 'gk')],
        BillingMode='PAY_PER_REQUEST',
        LocalSecondaryIndexes=[
            {'IndexName': _LSI_INCLUDE,
             'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                           {'AttributeName': 'li', 'KeyType': 'RANGE'}],
             'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['kept_l']}},
            {'IndexName': _LSI_ALL,
             'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                           {'AttributeName': 'la', 'KeyType': 'RANGE'}],
             'Projection': {'ProjectionType': 'ALL'}},
        ],
        GlobalSecondaryIndexes=[
            {'IndexName': _GSI_INCLUDE,
             'KeySchema': [{'AttributeName': 'gi', 'KeyType': 'HASH'}],
             'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['kept_g']}},
            {'IndexName': _GSI_KEYS_ONLY,
             'KeySchema': [{'AttributeName': 'gk', 'KeyType': 'HASH'}],
             'Projection': {'ProjectionType': 'KEYS_ONLY'}},
        ],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- the declaration: DescribeTable echoes INCLUDE with its list, and nothing for the others ---
    desc = ddb.describe_table(TableName=t)['Table']
    lsis = {i['IndexName']: i['Projection'] for i in desc['LocalSecondaryIndexes']}
    gsis = {i['IndexName']: i['Projection'] for i in desc['GlobalSecondaryIndexes']}

    assert lsis.get(_LSI_INCLUDE) == {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['kept_l']}, (
        f'DescribeTable must echo the LSI INCLUDE projection together with its NonKeyAttributes, got '
        f'{lsis.get(_LSI_INCLUDE)!r}'
    )
    assert gsis.get(_GSI_INCLUDE) == {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['kept_g']}, (
        f'DescribeTable must echo the GSI INCLUDE projection together with its NonKeyAttributes, got '
        f'{gsis.get(_GSI_INCLUDE)!r}'
    )
    assert lsis.get(_LSI_ALL) == {'ProjectionType': 'ALL'}, (
        f'an ALL projection names no attributes, so DescribeTable must carry no NonKeyAttributes '
        f'member for it, got {lsis.get(_LSI_ALL)!r}'
    )
    assert gsis.get(_GSI_KEYS_ONLY) == {'ProjectionType': 'KEYS_ONLY'}, (
        f'a KEYS_ONLY projection names no attributes, so DescribeTable must carry no '
        f'NonKeyAttributes member for it, got {gsis.get(_GSI_KEYS_ONLY)!r}'
    )

    # --- one item carrying every attribute the projections divide up ---
    ddb.put_item(TableName=t, Item={
        'pk': {'S': 'p'}, 'sk': {'S': 's'},
        'li': {'S': 'lv'}, 'la': {'S': 'av'}, 'gi': {'S': 'gv'}, 'gk': {'S': 'kv'},
        'kept_l': {'S': 'KL'}, 'kept_g': {'S': 'KG'}, 'excluded': {'S': 'X'},
    })
    base = ddb.get_item(TableName=t, Key={'pk': {'S': 'p'}, 'sk': {'S': 's'}},
                        ConsistentRead=True).get('Item', {})
    assert base.get('excluded') == {'S': 'X'}, (
        f"the base item must really carry 'excluded', or the absences asserted below are vacuous: "
        f'{base!r}'
    )

    # --- the INCLUDE LSI serves exactly the projected attribute set ---
    lsi_item = ddb.query(TableName=t, IndexName=_LSI_INCLUDE, KeyConditionExpression='pk = :p',
                         ExpressionAttributeValues={':p': {'S': 'p'}},
                         ConsistentRead=True)['Items'][0]
    assert sorted(lsi_item) == ['kept_l', 'li', 'pk', 'sk'], (
        f'an INCLUDE LSI projects the table key, its own range key and the named attributes and '
        f'nothing else, got {sorted(lsi_item)!r}'
    )
    assert lsi_item.get('kept_l') == {'S': 'KL'}, (
        f'the INCLUDEd attribute must be projected with its value, got {lsi_item.get("kept_l")!r}'
    )
    assert 'excluded' not in lsi_item, (
        f'an attribute outside the INCLUDE list must not be served by the index, got {lsi_item!r}'
    )

    # --- the ALL LSI on the same item does serve it: the absence above is the projection's doing ---
    all_item = ddb.query(TableName=t, IndexName=_LSI_ALL, KeyConditionExpression='pk = :p',
                         ExpressionAttributeValues={':p': {'S': 'p'}},
                         ConsistentRead=True)['Items'][0]
    assert all_item.get('excluded') == {'S': 'X'}, (
        f'control: an ALL projection over the same item must serve the excluded attribute, so the '
        f'INCLUDE absences are attributable to the projection and not to index reads generally; got '
        f'{all_item!r}'
    )

    # --- the same rule on a global secondary index, once it has caught up ---
    gsi_resp = _poll(
        lambda: ddb.query(TableName=t, IndexName=_GSI_INCLUDE, KeyConditionExpression='gi = :g',
                          ExpressionAttributeValues={':g': {'S': 'gv'}}),
        lambda r: r['Count'] == 1, timeout_s=120,
        description=f'the item propagating into {_GSI_INCLUDE}')
    gsi_item = gsi_resp['Items'][0]
    assert sorted(gsi_item) == ['gi', 'kept_g', 'pk', 'sk'], (
        f'an INCLUDE GSI projects the table key, its own key and the named attributes and nothing '
        f'else, got {sorted(gsi_item)!r}'
    )
    assert gsi_item.get('kept_g') == {'S': 'KG'}, (
        f'the INCLUDEd attribute must be projected with its value, got {gsi_item.get("kept_g")!r}'
    )
    assert 'excluded' not in gsi_item, (
        f'an attribute outside the GSI INCLUDE list must not be served by the index, got {gsi_item!r}'
    )

    keys_resp = _poll(
        lambda: ddb.query(TableName=t, IndexName=_GSI_KEYS_ONLY, KeyConditionExpression='gk = :g',
                          ExpressionAttributeValues={':g': {'S': 'kv'}}),
        lambda r: r['Count'] == 1, timeout_s=120,
        description=f'the item propagating into {_GSI_KEYS_ONLY}')
    keys_item = keys_resp['Items'][0]
    assert sorted(keys_item) == ['gk', 'pk', 'sk'], (
        f'a KEYS_ONLY GSI projects the table key and its own key and nothing else, got '
        f'{sorted(keys_item)!r}'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
