"""partiql-select-index-qualified-capacity-table-and-index-arms."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "partiql-select-index-qualified-capacity-table-and-index-arms"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_GSI = 'gsi1'
_LSI_KEYS = 'lsi-keys'
_LSI_INC = 'lsi-inc'
_PAYLOAD_LEN = 50
# Every item is far below 4 KB. An index read rounds the summed size of the rows it reads up to
# 4 KB: 1 RCU strongly consistent, 0.5 eventually consistent. A fetch back into the base table
# rounds each fetched item up to 4 KB on its own: 1 RCU per item strongly consistent.
_INDEX_RCU_STRONG = 1.0
_INDEX_RCU_EVENTUAL = 0.5
_FETCH_RCU_STRONG_PER_ITEM = 1.0


def _wait_table_and_gsi_active(ctx, ddb, table_name, gsi_name):
    """Poll DescribeTable until the table and the named GSI are both ACTIVE."""
    left = ctx.time_left()
    budget_s = 180.0 if left is None else max(5.0, min(180.0, left - 10.0))
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table_name)['Table']
        gsis = {i['IndexName']: i['IndexStatus'] for i in last.get('GlobalSecondaryIndexes', [])}
        if last['TableStatus'] == 'ACTIVE' and gsis.get(gsi_name) == 'ACTIVE':
            return last
        time.sleep(2.0)
    raise AssertionError(f'table/GSI {table_name}/{gsi_name} never went ACTIVE in {budget_s}s: {last!r}')


def _select_settled(ctx, fn, want: int, description: str, cap_s: float = 90.0):
    """Poll an ExecuteStatement call until it returns ``want`` items (a GSI fan-out is eventually
    consistent, so it may need a moment to settle before capacity is measured against it)."""
    left = ctx.time_left()
    budget_s = cap_s if left is None else max(1.0, min(cap_s, left - 5.0))
    deadline = time.monotonic() + budget_s
    while True:
        resp = fn()
        if len(resp.get('Items', [])) >= want:
            return resp
        if time.monotonic() >= deadline:
            raise AssertionError(
                f'{description} did not settle to {want} item(s) within {budget_s:.0f}s; '
                f'last count={len(resp.get("Items", []))!r}'
            )
        time.sleep(1.0)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A PartiQL SELECT through a GSI or LSI bills the index arm and nothing on the Table arm
    when every selected attribute is in the projection; naming one an INCLUDE LSI omits adds a
    Table arm, ConsistentRead doubles both, a non-matching filter does not shrink it, Limit does.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CapacityUnitCalculations.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlcap-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gpk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk_keys', 'AttributeType': 'N'},
            {'AttributeName': 'lsk_inc', 'AttributeType': 'N'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': _GSI,
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        LocalSecondaryIndexes=[
            {
                'IndexName': _LSI_KEYS,
                'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                              {'AttributeName': 'lsk_keys', 'KeyType': 'RANGE'}],
                'Projection': {'ProjectionType': 'KEYS_ONLY'},
            },
            {
                'IndexName': _LSI_INC,
                'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                              {'AttributeName': 'lsk_inc', 'KeyType': 'RANGE'}],
                'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['category']},
            },
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_table_and_gsi_active(ctx, ddb, table, _GSI)

    items = 3
    for i in range(items):
        ddb.put_item(TableName=table, Item={
            'pk': {'S': 'P'}, 'sk': {'S': str(i)}, 'gpk': {'S': 'G'},
            'lsk_keys': {'N': str(i)}, 'lsk_inc': {'N': str(i)},
            'category': {'S': 'cat'}, 'extra': {'S': 'x' * _PAYLOAD_LEN},
        })

    # A keyed GSI read charges the GSI arm and nothing on the Table arm.
    gsi_resp = _select_settled(
        ctx,
        lambda: ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}"."{_GSI}" WHERE gpk = ?',
            Parameters=[{'S': 'G'}], ReturnConsumedCapacity='INDEXES'),
        want=items, description='keyed GSI SELECT',
    )
    cc = gsi_resp['ConsumedCapacity']
    assert cc['Table']['CapacityUnits'] == 0, (
        f'a keyed GSI SELECT must charge the Table arm nothing, got {cc["Table"]!r}'
    )
    assert cc['GlobalSecondaryIndexes'][_GSI]['CapacityUnits'] == _INDEX_RCU_EVENTUAL, (
        f'the GSI arm must carry the {_INDEX_RCU_EVENTUAL!r} RCU read, got {cc["GlobalSecondaryIndexes"]!r}'
    )
    assert cc['CapacityUnits'] == _INDEX_RCU_EVENTUAL, (
        f'the keyed GSI SELECT must cost {_INDEX_RCU_EVENTUAL!r} RCU in total, got {cc!r}'
    )

    # SELECT * against a KEYS_ONLY LSI likewise charges no Table arm: every selected attribute is
    # the table's or the index's own key.
    keys_only = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}"."{_LSI_KEYS}" WHERE pk = ?',
        Parameters=[{'S': 'P'}], ReturnConsumedCapacity='INDEXES', ConsistentRead=True,
    )
    cc = keys_only['ConsumedCapacity']
    assert len(keys_only['Items']) == items, f'expected all {items} items, got {len(keys_only["Items"])}'
    assert cc['Table']['CapacityUnits'] == 0, (
        f'SELECT * on a KEYS_ONLY LSI must charge the Table arm nothing, got {cc["Table"]!r}'
    )
    assert cc['LocalSecondaryIndexes'][_LSI_KEYS]['CapacityUnits'] == _INDEX_RCU_STRONG, (
        f'the LSI arm must carry the {_INDEX_RCU_STRONG!r} RCU read, got {cc["LocalSecondaryIndexes"]!r}'
    )
    assert cc['CapacityUnits'] == _INDEX_RCU_STRONG, (
        f'SELECT * on a KEYS_ONLY LSI must cost {_INDEX_RCU_STRONG!r} RCU in total, got {cc!r}'
    )

    # Naming 'extra' -- not in the INCLUDE projection -- through the LSI adds a nonzero Table arm
    # for the reach-back into the base table, strongly consistent.
    reach_strong = ddb.execute_statement(
        Statement=f'SELECT pk, sk, extra FROM "{table}"."{_LSI_INC}" WHERE pk = ?',
        Parameters=[{'S': 'P'}], ReturnConsumedCapacity='INDEXES', ConsistentRead=True,
    )
    cc = reach_strong['ConsumedCapacity']
    assert len(reach_strong['Items']) == items, f'expected all {items} items, got {len(reach_strong["Items"])}'
    table_strong = cc['Table']['CapacityUnits']
    assert table_strong == items * _FETCH_RCU_STRONG_PER_ITEM, (
        f'naming an unprojected attribute through an LSI must add a Table arm of '
        f'{items * _FETCH_RCU_STRONG_PER_ITEM!r} RCU, one per fetched item, got {cc["Table"]!r}'
    )
    lsi_strong = cc['LocalSecondaryIndexes'][_LSI_INC]['CapacityUnits']
    assert lsi_strong == _INDEX_RCU_STRONG, (
        f'the LSI arm of the reach-back must be {_INDEX_RCU_STRONG!r} RCU, got {cc["LocalSecondaryIndexes"]!r}'
    )

    # ConsistentRead doubles both the Table and the LSI arm of that same reach-back.
    reach_eventual = ddb.execute_statement(
        Statement=f'SELECT pk, sk, extra FROM "{table}"."{_LSI_INC}" WHERE pk = ?',
        Parameters=[{'S': 'P'}], ReturnConsumedCapacity='INDEXES',
    )
    cc = reach_eventual['ConsumedCapacity']
    assert cc['Table']['CapacityUnits'] == table_strong / 2, (
        f'eventual consistency must halve the Table arm from {table_strong!r}, got {cc["Table"]!r}'
    )
    assert cc['LocalSecondaryIndexes'][_LSI_INC]['CapacityUnits'] == lsi_strong / 2, (
        f'eventual consistency must halve the LSI arm from {lsi_strong!r}, got '
        f'{cc["LocalSecondaryIndexes"]!r}'
    )

    # A WHERE term on the projected 'category' attribute that matches nothing still walks every
    # row for the reach-back: the cost is identical to the unfiltered read above, not lower.
    filtered = ddb.execute_statement(
        Statement=f'SELECT pk, sk, extra FROM "{table}"."{_LSI_INC}" WHERE pk = ? AND category = ?',
        Parameters=[{'S': 'P'}, {'S': 'no-such-category'}],
        ReturnConsumedCapacity='INDEXES', ConsistentRead=True,
    )
    assert filtered['Items'] == [], f'the nonmatching filter must return no items, got {filtered["Items"]!r}'
    cc = filtered['ConsumedCapacity']
    assert cc['Table']['CapacityUnits'] == table_strong, (
        f'a filter that matches nothing must still cost the full reach-back {table_strong!r} '
        f'(rows walked, not rows returned), got {cc["Table"]!r}'
    )
    assert cc['LocalSecondaryIndexes'][_LSI_INC]['CapacityUnits'] == lsi_strong, (
        f'the LSI arm of the filtered reach-back must match the unfiltered {lsi_strong!r}, got '
        f'{cc["LocalSecondaryIndexes"]!r}'
    )

    # Limit=1 examines and fetches only one row.
    limited = ddb.execute_statement(
        Statement=f'SELECT pk, sk, extra FROM "{table}"."{_LSI_INC}" WHERE pk = ?',
        Parameters=[{'S': 'P'}], ReturnConsumedCapacity='INDEXES', ConsistentRead=True, Limit=1,
    )
    assert len(limited['Items']) == 1, f'Limit=1 must return exactly 1 item, got {limited["Items"]!r}'
    cc = limited['ConsumedCapacity']
    assert cc['Table']['CapacityUnits'] == _FETCH_RCU_STRONG_PER_ITEM, (
        f'Limit=1 must fetch one item for {_FETCH_RCU_STRONG_PER_ITEM!r} RCU on the Table arm, got '
        f'{cc["Table"]!r}'
    )
    assert cc['LocalSecondaryIndexes'][_LSI_INC]['CapacityUnits'] == _INDEX_RCU_STRONG, (
        f'Limit=1 must read {_INDEX_RCU_STRONG!r} RCU on the LSI arm, got {cc["LocalSecondaryIndexes"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
