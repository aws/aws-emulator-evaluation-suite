"""partiql-select-keys-only-gsi-and-projected-attribute-list-lsi-charge-no-table-arm."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "partiql-select-keys-only-gsi-and-projected-attribute-list-lsi-charge-no-table-arm"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_GSI = 'gsi-keys-only'
_LSI = 'lsi-inc'
# Every item is far below 4 KB, so an index read rounds the summed size of the rows it reads up to
# 4 KB once: 1 RCU strongly consistent, 0.5 RCU eventually consistent.
_INDEX_RCU_STRONG = 1.0
_INDEX_RCU_EVENTUAL = 0.5


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
        if len(resp.get('Items', [])) == want:
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
    """A PartiQL SELECT * through a KEYS_ONLY GSI charges nothing on the Table arm, and naming
    only an LSI's projected attributes (base keys plus its INCLUDE list) likewise charges nothing
    on the Table arm; both charge only their index arm.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CapacityUnitCalculations.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlproj-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gpk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'N'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': _GSI,
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        LocalSecondaryIndexes=[{
            'IndexName': _LSI,
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['category']},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_table_and_gsi_active(ctx, ddb, table, _GSI)

    items = 3
    for i in range(items):
        ddb.put_item(TableName=table, Item={
            'pk': {'S': 'P'}, 'sk': {'S': str(i)}, 'gpk': {'S': 'G'}, 'lsk': {'N': str(i)},
            'category': {'S': 'cat'}, 'extra': {'S': 'unprojected-value'},
        })

    # SELECT * against a KEYS_ONLY GSI charges no Table arm: every selected attribute -- the
    # table key and the GSI's own key -- is already in the index entry.
    gsi_resp = _select_settled(
        ctx,
        lambda: ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}"."{_GSI}" WHERE gpk = ?',
            Parameters=[{'S': 'G'}], ReturnConsumedCapacity='INDEXES'),
        want=items, description='keys-only GSI SELECT *',
    )
    assert len(gsi_resp['Items']) == items, f'expected all {items} items, got {len(gsi_resp["Items"])}'
    for item in gsi_resp['Items']:
        assert set(item) == {'pk', 'sk', 'gpk'}, (
            f'SELECT * through a KEYS_ONLY GSI must project only the table and index keys, got '
            f'{sorted(item)!r}'
        )
    cc = gsi_resp['ConsumedCapacity']
    assert cc['Table']['CapacityUnits'] == 0, (
        f'SELECT * on a KEYS_ONLY GSI must charge the Table arm nothing, got {cc["Table"]!r}'
    )
    assert cc['GlobalSecondaryIndexes'][_GSI]['CapacityUnits'] == _INDEX_RCU_EVENTUAL, (
        f'the GSI arm must carry the {_INDEX_RCU_EVENTUAL!r} RCU read, got {cc["GlobalSecondaryIndexes"]!r}'
    )
    assert cc['CapacityUnits'] == _INDEX_RCU_EVENTUAL, (
        f'SELECT * on a KEYS_ONLY GSI must cost {_INDEX_RCU_EVENTUAL!r} RCU in total, got {cc!r}'
    )

    # Naming only the LSI's projected attributes -- the table keys plus its INCLUDE list -- charges
    # no Table arm either: nothing selected needs a reach-back into the base table.
    lsi_resp = ddb.execute_statement(
        Statement=f'SELECT pk, sk, category FROM "{table}"."{_LSI}" WHERE pk = ?',
        Parameters=[{'S': 'P'}], ReturnConsumedCapacity='INDEXES', ConsistentRead=True,
    )
    assert len(lsi_resp['Items']) == items, f'expected all {items} items, got {len(lsi_resp["Items"])}'
    for item in lsi_resp['Items']:
        assert set(item) == {'pk', 'sk', 'category'}, (
            f'naming only the projected attributes must return exactly those, got {sorted(item)!r}'
        )
        assert item['category'] == {'S': 'cat'}, f'expected category=cat, got {item["category"]!r}'
    cc = lsi_resp['ConsumedCapacity']
    assert cc['Table']['CapacityUnits'] == 0, (
        f'naming only an LSI\'s projected attributes must charge the Table arm nothing, got '
        f'{cc["Table"]!r}'
    )
    assert cc['LocalSecondaryIndexes'][_LSI]['CapacityUnits'] == _INDEX_RCU_STRONG, (
        f'the LSI arm must carry the {_INDEX_RCU_STRONG!r} RCU read, got {cc["LocalSecondaryIndexes"]!r}'
    )
    assert cc['CapacityUnits'] == _INDEX_RCU_STRONG, (
        f'naming only the projected attributes through the LSI must cost {_INDEX_RCU_STRONG!r} RCU '
        f'in total, got {cc!r}'
    )

    # Contrast: naming an attribute outside the INCLUDE list, through the same LSI and the same
    # keys, bills the Table arm one read per fetched item -- proving the zero above is a property
    # of the attribute list, not of the index or the read path.
    reach_back = ddb.execute_statement(
        Statement=f'SELECT pk, sk, extra FROM "{table}"."{_LSI}" WHERE pk = ?',
        Parameters=[{'S': 'P'}], ReturnConsumedCapacity='INDEXES', ConsistentRead=True,
    )
    assert len(reach_back['Items']) == items, f'expected all {items} items, got {len(reach_back["Items"])}'
    assert reach_back['ConsumedCapacity']['Table']['CapacityUnits'] == _INDEX_RCU_STRONG * items, (
        f"naming 'extra', which the LSI does not project, must bill the Table arm one strongly "
        f"consistent 4 KB read per fetched item, {_INDEX_RCU_STRONG * items!r} RCU; got "
        f'{reach_back["ConsumedCapacity"]["Table"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
