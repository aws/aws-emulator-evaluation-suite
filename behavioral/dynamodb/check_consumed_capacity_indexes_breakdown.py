"""consumed-capacity-indexes-breakdown."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "consumed-capacity-indexes-breakdown"
GROUP = 'expressions'
SERVICES = ['dynamodb']

_INDEX = 'gsi-by-cat'


def _poll(fn, pred, *, timeout_s, interval_s=1.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f'{description} not met within {timeout_s}s. Last: {val!r}')
        time.sleep(interval_s)
        val = fn()
    return val


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReturnConsumedCapacity=INDEXES reports per-index capacity: a write to a GSI table charges Table and
    the GSI, a Query served by the GSI charges the GSI and no Table capacity, the same Query with TOTAL
    returns only the aggregate, and NONE returns no ConsumedCapacity."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-idx-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'cat', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
        GlobalSecondaryIndexes=[{
            'IndexName': _INDEX,
            'KeySchema': [{'AttributeName': 'cat', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- a base-table write fans out to the GSI: both must be itemized ---
    put = ddb.put_item(
        TableName=t,
        Item={'pk': {'S': 'i1'}, 'cat': {'S': 'c1'}, 'payload': {'S': 'p'}},
        ReturnConsumedCapacity='INDEXES',
    )
    cc = put.get('ConsumedCapacity')
    assert cc is not None, 'ReturnConsumedCapacity=INDEXES must return ConsumedCapacity'
    assert cc.get('TableName') == t, f'ConsumedCapacity.TableName must be {t}, got {cc.get("TableName")}'
    assert cc.get('CapacityUnits', 0) > 0, f'aggregate CapacityUnits must be > 0, got {cc.get("CapacityUnits")}'
    assert 'Table' in cc, (
        f'INDEXES must itemize the base table under "Table", got members {sorted(cc)}'
    )
    assert cc['Table'].get('CapacityUnits', 0) > 0, (
        f'base-table CapacityUnits must be > 0 for a table write, got {cc["Table"]}'
    )
    assert 'GlobalSecondaryIndexes' in cc, (
        f'INDEXES must itemize the GSI fan-out under "GlobalSecondaryIndexes", got members {sorted(cc)}'
    )
    assert _INDEX in cc['GlobalSecondaryIndexes'], (
        f'the breakdown must be keyed by index name {_INDEX}, got '
        f'{sorted(cc["GlobalSecondaryIndexes"])}'
    )
    assert cc['GlobalSecondaryIndexes'][_INDEX].get('CapacityUnits', 0) > 0, (
        f'a write that fans out to {_INDEX} must charge that index; got '
        f'{cc["GlobalSecondaryIndexes"][_INDEX]}'
    )

    # --- a Query SERVED BY the GSI charges the index, not the base table ---
    def _gsi_query(rcc):
        return ddb.query(
            TableName=t, IndexName=_INDEX,
            KeyConditionExpression='cat = :c',
            ExpressionAttributeValues={':c': {'S': 'c1'}},
            ReturnConsumedCapacity=rcc,
        )

    # GSIs are eventually consistent; wait for the item to land before asserting capacity.
    indexed = _poll(
        lambda: _gsi_query('INDEXES'),
        lambda r: r['Count'] == 1,
        timeout_s=90,
        interval_s=2.0,
        description=f'item propagated into {_INDEX}',
    )
    cc = indexed.get('ConsumedCapacity')
    assert cc is not None, 'a GSI Query with INDEXES must return ConsumedCapacity'
    assert cc.get('TableName') == t, f'ConsumedCapacity.TableName must be {t}, got {cc.get("TableName")}'
    assert 'GlobalSecondaryIndexes' in cc and _INDEX in cc['GlobalSecondaryIndexes'], (
        f'a Query on {_INDEX} must itemize that index, got members {sorted(cc)}'
    )
    assert cc['GlobalSecondaryIndexes'][_INDEX].get('CapacityUnits', 0) > 0, (
        f'the index read must be charged, got {cc["GlobalSecondaryIndexes"][_INDEX]}'
    )
    assert cc.get('Table', {}).get('CapacityUnits', 0) == 0, (
        f'a Query served by an ALL-projection GSI reads no base-table item and must charge no '
        f'base-table capacity, got Table={cc.get("Table")}'
    )

    # --- =TOTAL returns the aggregate with NO breakdown members ---
    total = _gsi_query('TOTAL')
    cc = total.get('ConsumedCapacity')
    assert cc is not None, 'a GSI Query with TOTAL must return ConsumedCapacity'
    assert cc.get('CapacityUnits', 0) > 0, f'TOTAL must report a positive aggregate, got {cc}'
    assert 'GlobalSecondaryIndexes' not in cc, (
        f'TOTAL must NOT include the per-index breakdown, got {cc.get("GlobalSecondaryIndexes")}'
    )
    assert 'Table' not in cc, f'TOTAL must NOT include the per-table breakdown, got {cc.get("Table")}'

    # --- =NONE on the same call omits ConsumedCapacity entirely ---
    none_resp = _gsi_query('NONE')
    assert 'ConsumedCapacity' not in none_resp, (
        f'NONE must omit ConsumedCapacity, got {none_resp.get("ConsumedCapacity")}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
