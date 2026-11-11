"""query-indexes-capacity-sums-bytes-once-across-table-gsi-and-lsi."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-indexes-capacity-sums-bytes-once-across-table-gsi-and-lsi"
GROUP = 'capacity'
SERVICES = ['dynamodb']

_GSI = 'gsi1'
_LSI = 'lsi1'

# Three items landing on exact 1 KB / 5 KB / 9 KB raw byte totals -- all inside the 1-9 KB band --
# chosen so the *sum-then-round-once* rule (ceil(total_bytes / 4096)) disagrees with a per-item
# ceil-then-sum bug: ceil(1024/4096)+ceil(5120/4096)+ceil(9216/4096) = 1+2+3 = 6, but the documented
# rule rounds the SUM once: ceil(15360/4096) = 4. A target that rounds per item instead of once
# over the total reports 6 (strong) / 3.0 (eventual) here, not 4 / 2.0.
_SIZES = (1024, 5120, 9216)
_PK = 'P'
_GPK = 'G'

# Fixed-length attribute names/values whose byte cost (len(name) + len(value)) is identical on
# every item, so only the payload length controls each item's total size.
_FIXED_OVERHEAD = (len('pk') + len(_PK)) + (len('gpk') + len(_GPK))
_RANGE_OVERHEAD = (len('sk') + 1) + (len('lsk') + 1)
_PAYLOAD_NAME_BYTES = len('payload')


def _item(i: int, size: int) -> dict:
    digit = str(i)
    payload_len = size - _FIXED_OVERHEAD - _RANGE_OVERHEAD - _PAYLOAD_NAME_BYTES
    assert payload_len > 0, f'size {size} too small for the fixed attribute overhead'
    return {
        'pk': {'S': _PK},
        'sk': {'S': digit},
        'gpk': {'S': _GPK},
        'lsk': {'S': digit},
        'payload': {'S': 'x' * payload_len},
    }


_TOTAL_BYTES = sum(_SIZES)
_STRONG_RCU = -(-_TOTAL_BYTES // 4096)  # ceil(total / 4096), rounding the SUM once
_EVENTUAL_RCU = _STRONG_RCU / 2


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _query_settled(ctx, fn, want: int, description: str, cap_s: float = 90.0):
    """Poll ``fn`` (a Query call) until it returns ``want`` items; a GSI write is eventually
    consistent, so the fan-out needs to land before capacity is measured against it."""
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    deadline = start + budget_s
    while True:
        resp = fn()
        if resp['Count'] >= want:
            return resp
        if time.monotonic() >= deadline:
            raise AssertionError(
                f'{description} did not settle to {want} item(s) within {budget_s:.0f}s; '
                f'last Count={resp["Count"]!r}'
            )
        time.sleep(1.0)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReturnConsumedCapacity=INDEXES on a Query bills the SUM of the examined items' raw bytes,
    rounded to the 4 KB boundary ONCE, identically whether answered by the base table, an
    ALL-projection LSI or GSI, and strongly or eventually consistent.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CapacityUnitCalculations.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-ccqix-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gpk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
        GlobalSecondaryIndexes=[{
            'IndexName': _GSI,
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        LocalSecondaryIndexes=[{
            'IndexName': _LSI,
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    items = [_item(i, size) for i, size in enumerate(_SIZES)]
    for item in items:
        ddb.put_item(TableName=table, Item=item)

    # --- the base table, strongly consistent: the ground-truth sum-once rounding ---
    table_strong = _query_settled(
        ctx,
        lambda: ddb.query(TableName=table, KeyConditionExpression='pk = :p',
                          ExpressionAttributeValues={':p': {'S': _PK}},
                          ConsistentRead=True, ReturnConsumedCapacity='INDEXES'),
        want=len(items), description='base-table strong Query',
    )
    assert 'LastEvaluatedKey' not in table_strong, (
        'this check compares single-page capacity; the base-table Query must not paginate at this size'
    )
    cc = table_strong['ConsumedCapacity']
    assert cc['CapacityUnits'] == _STRONG_RCU, (
        f'3 items totalling {_TOTAL_BYTES} raw bytes queried strongly consistently from the base '
        f'table must bill exactly ceil({_TOTAL_BYTES}/4096) = {_STRONG_RCU!r} RCU, got '
        f'{cc["CapacityUnits"]!r} -- a per-item-rounded responder would report '
        f'{sum(-(-s // 4096) for s in _SIZES)!r} instead'
    )
    assert cc['Table']['CapacityUnits'] == _STRONG_RCU, (
        f'the Table arm of the breakdown must carry the same {_STRONG_RCU!r} RCU as the aggregate, '
        f'got {cc["Table"]!r}'
    )
    assert 'GlobalSecondaryIndexes' not in cc and 'LocalSecondaryIndexes' not in cc, (
        f'a Query that names no IndexName must carry no per-index breakdown member, got {sorted(cc)!r}'
    )

    # --- the base table, eventually consistent: same bytes, half the units ---
    table_eventual = ddb.query(TableName=table, KeyConditionExpression='pk = :p',
                               ExpressionAttributeValues={':p': {'S': _PK}},
                               ReturnConsumedCapacity='INDEXES')
    cc = table_eventual['ConsumedCapacity']
    assert cc['CapacityUnits'] == _EVENTUAL_RCU, (
        f'the identical read at eventual consistency must bill exactly half of {_STRONG_RCU!r}, '
        f'{_EVENTUAL_RCU!r}, got {cc["CapacityUnits"]!r}'
    )
    assert cc['Table']['CapacityUnits'] == _EVENTUAL_RCU, (
        f'the Table arm must also halve to {_EVENTUAL_RCU!r}, got {cc["Table"]!r}'
    )

    # --- the LSI, strongly consistent: an LSI shares the base partition, so ConsistentRead=True
    #     is legal and must reproduce the base table's own strong number exactly ---
    lsi_strong = ddb.query(TableName=table, IndexName=_LSI, KeyConditionExpression='pk = :p',
                           ExpressionAttributeValues={':p': {'S': _PK}},
                           ConsistentRead=True, ReturnConsumedCapacity='INDEXES')
    assert lsi_strong['Count'] == len(items), (
        f'an ALL-projection LSI over the same partition must return all {len(items)} items, got '
        f'{lsi_strong["Count"]!r}'
    )
    cc = lsi_strong['ConsumedCapacity']
    assert cc['CapacityUnits'] == _STRONG_RCU, (
        f'the same 3 items, served by the ALL-projection LSI at strong consistency, must bill '
        f'exactly {_STRONG_RCU!r} RCU -- identical to the base-table number -- got '
        f'{cc["CapacityUnits"]!r}'
    )
    assert cc['LocalSecondaryIndexes'][_LSI]['CapacityUnits'] == _STRONG_RCU, (
        f'the LocalSecondaryIndexes[{_LSI!r}] arm must carry {_STRONG_RCU!r} RCU, got '
        f'{cc["LocalSecondaryIndexes"]!r}'
    )
    assert cc['Table']['CapacityUnits'] == 0, (
        f'an LSI-served Query reads no separate base-table copy and must charge the Table arm '
        f'nothing, got {cc["Table"]!r}'
    )

    # --- the LSI, eventually consistent: same bytes, half the units ---
    lsi_eventual = ddb.query(TableName=table, IndexName=_LSI, KeyConditionExpression='pk = :p',
                             ExpressionAttributeValues={':p': {'S': _PK}},
                             ReturnConsumedCapacity='INDEXES')
    cc = lsi_eventual['ConsumedCapacity']
    assert cc['CapacityUnits'] == _EVENTUAL_RCU, (
        f'the LSI read at eventual consistency must halve to {_EVENTUAL_RCU!r}, got '
        f'{cc["CapacityUnits"]!r}'
    )
    assert cc['LocalSecondaryIndexes'][_LSI]['CapacityUnits'] == _EVENTUAL_RCU, (
        f'the LocalSecondaryIndexes[{_LSI!r}] arm must also halve to {_EVENTUAL_RCU!r}, got '
        f'{cc["LocalSecondaryIndexes"]!r}'
    )

    # --- the GSI: always eventually consistent, same items via the gpk partition ---
    gsi_eventual = _query_settled(
        ctx,
        lambda: ddb.query(TableName=table, IndexName=_GSI, KeyConditionExpression='gpk = :g',
                          ExpressionAttributeValues={':g': {'S': _GPK}},
                          ReturnConsumedCapacity='INDEXES'),
        want=len(items), description='GSI Query fan-out',
    )
    assert 'LastEvaluatedKey' not in gsi_eventual, (
        'this check compares single-page capacity; the GSI Query must not paginate at this size'
    )
    cc = gsi_eventual['ConsumedCapacity']
    assert cc['CapacityUnits'] == _EVENTUAL_RCU, (
        f'the same 3 items, served by the ALL-projection GSI (necessarily eventually consistent), '
        f'must bill exactly {_EVENTUAL_RCU!r} RCU -- identical to the eventual base-table and LSI '
        f'numbers -- got {cc["CapacityUnits"]!r}'
    )
    assert cc['GlobalSecondaryIndexes'][_GSI]['CapacityUnits'] == _EVENTUAL_RCU, (
        f'the GlobalSecondaryIndexes[{_GSI!r}] arm must carry {_EVENTUAL_RCU!r} RCU, got '
        f'{cc["GlobalSecondaryIndexes"]!r}'
    )
    assert cc['Table']['CapacityUnits'] == 0, (
        f'a GSI-served Query must charge the Table arm nothing, got {cc["Table"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
