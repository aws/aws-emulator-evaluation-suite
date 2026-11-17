"""lsi-select-all-attributes-query-bills-base-table-per-item-across-multiple-items."""
from __future__ import annotations

import math

from behavioral_harness import tags

CHECK = "lsi-select-all-attributes-query-bills-base-table-per-item-across-multiple-items"
GROUP = 'lsi'
SERVICES = ['dynamodb']

_PK = 'P'

# Three items at distinct 1 KB / 5 KB / 9 KB raw-byte bands, each rounded to its own 4 KB
# boundary: ceil(1024/4096) + ceil(5120/4096) + ceil(9216/4096) = 1 + 2 + 3 = 6.
_SIZES = (1024, 5120, 9216)

# Fixed per-item overhead (attribute name + key value bytes) so only the payload length
# controls each item's total size.
_PK_BYTES = len('pk') + len(_PK)
_RANGE_BYTES = (len('sk') + 1) + (len('lsk') + 1)
_PAYLOAD_NAME_BYTES = len('payload')
_ITEM_OVERHEAD = _PK_BYTES + _RANGE_BYTES + _PAYLOAD_NAME_BYTES

# A KEYS_ONLY LSI entry carries only the base table's key and the index's own sort key -- no
# payload -- so its per-item size is fixed regardless of the payload length.
_INDEX_ONLY_ITEM_BYTES = _PK_BYTES + _RANGE_BYTES


def _item(i: int, size: int) -> dict:
    digit = str(i)
    payload_len = size - _ITEM_OVERHEAD
    assert payload_len > 0, f'size {size} too small for the fixed attribute overhead'
    return {
        'pk': {'S': _PK},
        'sk': {'S': digit},
        'lsk': {'S': digit},
        'payload': {'S': 'x' * payload_len},
    }


_TOTAL_ITEM_BYTES = sum(_SIZES)
_TABLE_RCU = sum(math.ceil(s / 4096) for s in _SIZES)
_TOTAL_INDEX_ONLY_BYTES = _INDEX_ONLY_ITEM_BYTES * len(_SIZES)
_LSI_RCU = math.ceil(_TOTAL_INDEX_ONLY_BYTES / 4096)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query on a KEYS_ONLY LSI with Select=ALL_ATTRIBUTES fetches every matching item from the
    base table and bills the Table arm the SUM of each item's OWN 4 KB-rounded size, on top of the
    unchanged index-only LocalSecondaryIndexes arm; omitting Select charges the Table arm nothing."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-lsiall-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'S'},
        ],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'KEYS_ONLY'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 250})

    items = [_item(i, size) for i, size in enumerate(_SIZES)]
    for item in items:
        ddb.put_item(TableName=table, Item=item)

    # Positive control: no Select at all defaults to ALL_PROJECTED_ATTRIBUTES on an index query,
    # which the KEYS_ONLY projection satisfies without touching the base table.
    bare = ddb.query(TableName=table, IndexName='lsi1', KeyConditionExpression='pk = :p',
                      ExpressionAttributeValues={':p': {'S': _PK}}, ConsistentRead=True,
                      ReturnConsumedCapacity='INDEXES')
    assert bare['Count'] == len(items), f'all {len(items)!r} items must match the partition, got {bare["Count"]!r}'
    assert 'LastEvaluatedKey' not in bare, 'this check compares single-page capacity; the Query must not paginate'
    for bare_item in bare['Items']:
        assert set(bare_item) == {'pk', 'sk', 'lsk'}, (
            f'a KEYS_ONLY LSI query with no Select must return only the keys, got {sorted(bare_item)!r}'
        )
    bare_cc = bare['ConsumedCapacity']
    assert bare_cc['CapacityUnits'] == _LSI_RCU, (
        f'the index-only read of {len(items)!r} items totalling {_TOTAL_INDEX_ONLY_BYTES!r} raw '
        f'bytes must bill exactly {_LSI_RCU!r} RCU, got {bare_cc["CapacityUnits"]!r}'
    )
    assert bare_cc.get('Table', {}).get('CapacityUnits', 0) == 0, (
        f'an index-only LSI read must charge the Table arm nothing, got {bare_cc.get("Table")!r}'
    )
    assert bare_cc['LocalSecondaryIndexes']['lsi1']['CapacityUnits'] == _LSI_RCU, (
        f"the LocalSecondaryIndexes['lsi1'] arm must carry {_LSI_RCU!r} RCU, got "
        f"{bare_cc['LocalSecondaryIndexes']!r}"
    )

    # The behaviour under test: Select=ALL_ATTRIBUTES forces a base-table fetch of every matching
    # item, and the Table arm bills the sum of each item's own 4 KB-rounded size.
    fetched = ddb.query(TableName=table, IndexName='lsi1', KeyConditionExpression='pk = :p',
                        Select='ALL_ATTRIBUTES',
                        ExpressionAttributeValues={':p': {'S': _PK}}, ConsistentRead=True,
                        ReturnConsumedCapacity='INDEXES')
    assert fetched['Count'] == len(items), f'all {len(items)!r} items must match, got {fetched["Count"]!r}'
    assert 'LastEvaluatedKey' not in fetched, 'this check compares single-page capacity; the Query must not paginate'
    fetched_by_sk = {i['sk']['S']: i for i in fetched['Items']}
    for idx, size in enumerate(_SIZES):
        digit = str(idx)
        fetched_item = fetched_by_sk[digit]
        expected_payload_len = size - _ITEM_OVERHEAD
        assert fetched_item.get('payload', {}).get('S') == 'x' * expected_payload_len, (
            f'Select=ALL_ATTRIBUTES must fetch the full item, including "payload", from the base '
            f'table, got {sorted(fetched_item)!r} for sk={digit!r}'
        )

    fetched_cc = fetched['ConsumedCapacity']
    assert fetched_cc['Table']['CapacityUnits'] == _TABLE_RCU, (
        f'the base-table fetch of {len(items)!r} items sized {_SIZES!r} raw bytes must bill the '
        f'SUM of each item\'s own 4 KB-rounded size on the Table arm, '
        f'{" + ".join(str(math.ceil(s / 4096)) for s in _SIZES)} = {_TABLE_RCU!r} RCU, got '
        f'{fetched_cc["Table"]!r}'
    )
    assert fetched_cc['LocalSecondaryIndexes']['lsi1']['CapacityUnits'] == _LSI_RCU, (
        f"the LocalSecondaryIndexes['lsi1'] arm must still carry the unchanged index-only "
        f"{_LSI_RCU!r} RCU, got {fetched_cc['LocalSecondaryIndexes']!r}"
    )
    assert fetched_cc['CapacityUnits'] == _TABLE_RCU + _LSI_RCU, (
        f'the total must be the base-table fetch PLUS the unchanged index-only read: '
        f'{_TABLE_RCU!r} + {_LSI_RCU!r} = {_TABLE_RCU + _LSI_RCU!r}, got {fetched_cc["CapacityUnits"]!r}'
    )
    assert fetched_cc['CapacityUnits'] - bare_cc['CapacityUnits'] == _TABLE_RCU, (
        f'the Select=ALL_ATTRIBUTES Query must exceed the index-only read by exactly the base '
        f"items' per-item-rounded size, {_TABLE_RCU!r} RCU, got a difference of "
        f'{fetched_cc["CapacityUnits"] - bare_cc["CapacityUnits"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
