"""partiql-partition-key-predicate-is-planned-as-a-query-not-a-scan."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-partition-key-predicate-is-planned-as-a-query-not-a-scan"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_PARTITIONS = 10
_PER_PARTITION = 30
_PAYLOAD = 'y' * 900             # ≈1 KB item, so the whole table is ≈300 KB: one page, many RCU
_TARGET_PARTITION = 'P#03'


def _drain_batch(ddb, table, requests, *, attempts=30):
    """BatchWriteItem until UnprocessedItems is empty; raises rather than silently under-writing."""
    pending = {table: list(requests)}
    for _ in range(attempts):
        if not pending:
            return
        pending = ddb.batch_write_item(RequestItems=pending).get('UnprocessedItems') or {}
    raise AssertionError(f'BatchWriteItem never drained UnprocessedItems: {pending!r}')


def _ids(items):
    """The (pk, sk) identity of every returned item, sorted -- the plan-independent answer."""
    return sorted((i['pk']['S'], int(i['sk']['N'])) for i in items)


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL SELECT pinning the partition key bills like the equivalent Query; on a non-key
    attribute it bills like a filtered full Scan, though both return the same items.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.select.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqplan-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'sk', 'AttributeType': 'N'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real:managed', 'Value': 'true'},
              {'Key': 'sim2real:check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # `tag` mirrors `pk` in VALUE but is not part of any key, so the two predicates below select the
    # same items through different plans.
    for p in range(_PARTITIONS):
        pk = f'P#{p:02d}'
        for offset in range(0, _PER_PARTITION, 25):
            _drain_batch(ddb, table, [
                {'PutRequest': {'Item': {
                    'pk': {'S': pk},
                    'sk': {'N': str(s)},
                    'tag': {'S': pk},
                    'payload': {'S': _PAYLOAD},
                }}}
                for s in range(offset, min(offset + 25, _PER_PARTITION))
            ])

    expected_ids = sorted((_TARGET_PARTITION, s) for s in range(_PER_PARTITION))

    # Reference capacities come from the low-level plans on the same data; every read is strongly
    # consistent so no 0.5x eventual-read factor enters one side only.
    native_query = ddb.query(
        TableName=table,
        KeyConditionExpression='pk = :p',
        ExpressionAttributeValues={':p': {'S': _TARGET_PARTITION}},
        ConsistentRead=True,
        ReturnConsumedCapacity='TOTAL',
    )
    native_filtered_scan = ddb.scan(
        TableName=table,
        FilterExpression='tag = :p',
        ExpressionAttributeValues={':p': {'S': _TARGET_PARTITION}},
        ConsistentRead=True,
        ReturnConsumedCapacity='TOTAL',
    )
    native_full_scan = ddb.scan(
        TableName=table, ConsistentRead=True, ReturnConsumedCapacity='TOTAL',
    )
    for label, resp in (('Query(pk = :p)', native_query),
                        ('Scan(FilterExpression tag = :p)', native_filtered_scan),
                        ('Scan(unfiltered)', native_full_scan)):
        assert 'LastEvaluatedKey' not in resp, (
            f'this check compares single-page capacity, so {label} must not paginate at this table '
            f'size; it returned LastEvaluatedKey {resp.get("LastEvaluatedKey")!r}'
        )
    query_cap = native_query['ConsumedCapacity']['CapacityUnits']
    filtered_scan_cap = native_filtered_scan['ConsumedCapacity']['CapacityUnits']
    full_scan_cap = native_full_scan['ConsumedCapacity']['CapacityUnits']

    assert _ids(native_query['Items']) == expected_ids, (
        f'the reference Query must return the {_PER_PARTITION!r} items of {_TARGET_PARTITION!r}, '
        f'got {len(native_query["Items"])!r}'
    )
    assert _ids(native_filtered_scan['Items']) == expected_ids, (
        f'the reference filtered Scan must return the same {_PER_PARTITION!r} items, got '
        f'{len(native_filtered_scan["Items"])!r}'
    )
    assert filtered_scan_cap == full_scan_cap, (
        f'a FilterExpression is applied after the read, so a filtered Scan must bill the same as the '
        f'unfiltered Scan of the same table: filtered {filtered_scan_cap!r} vs unfiltered '
        f'{full_scan_cap!r}'
    )
    # The experiment is only meaningful if the two low-level plans really cost differently here.
    assert full_scan_cap > query_cap, (
        f'this table is not big enough to distinguish the plans on this target: a full Scan billed '
        f'{full_scan_cap!r} and a single-partition Query billed {query_cap!r}. Nothing below can '
        f'discriminate; grow _PARTITIONS.'
    )

    # --- the same two plans, expressed in PartiQL ---
    pq_key = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE pk = ?',
        Parameters=[{'S': _TARGET_PARTITION}],
        ConsistentRead=True,
        ReturnConsumedCapacity='TOTAL',
    )
    pq_nonkey = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE tag = ?',
        Parameters=[{'S': _TARGET_PARTITION}],
        ConsistentRead=True,
        ReturnConsumedCapacity='TOTAL',
    )
    for label, resp in (('WHERE pk = ?', pq_key), ('WHERE tag = ?', pq_nonkey)):
        assert 'NextToken' not in resp, (
            f'this check compares single-page capacity, so the PartiQL SELECT {label} must not '
            f'paginate at this table size; it returned NextToken {resp.get("NextToken")!r}'
        )

    # Both statements must answer the SAME question -- otherwise a cheap number means nothing.
    assert _ids(pq_key['Items']) == expected_ids, (
        f'SELECT ... WHERE pk = ? must return the {_PER_PARTITION!r} items of '
        f'{_TARGET_PARTITION!r}, got {_ids(pq_key["Items"])[:5]!r} ({len(pq_key["Items"])!r} items)'
    )
    assert _ids(pq_nonkey['Items']) == expected_ids, (
        f'SELECT ... WHERE tag = ? selects the same {_PER_PARTITION!r} items by a non-key attribute, '
        f'got {len(pq_nonkey["Items"])!r} items'
    )

    pq_key_cap = pq_key['ConsumedCapacity']['CapacityUnits']
    pq_nonkey_cap = pq_nonkey['ConsumedCapacity']['CapacityUnits']

    assert pq_key_cap == query_cap, (
        f'a SELECT whose WHERE clause pins the partition key must be planned as a Query and bill '
        f'what the equivalent Query billed on this very data: PartiQL {pq_key_cap!r} vs Query '
        f'{query_cap!r} (a full Scan of this table bills {full_scan_cap!r}, so a PartiQL number near '
        f'that means the statement was scanned and filtered in memory)'
    )
    assert pq_nonkey_cap == filtered_scan_cap, (
        f'a SELECT with no partition-key equality must be planned as a full table Scan and bill what '
        f'the equivalent filtered Scan billed: PartiQL {pq_nonkey_cap!r} vs Scan '
        f'{filtered_scan_cap!r} (a single-partition Query bills {query_cap!r}, so a PartiQL number '
        f'near that means the non-key predicate was resolved through an index that does not exist)'
    )
    assert pq_nonkey_cap > pq_key_cap, (
        f'the two statements return identical items and must nevertheless cost differently, because '
        f'they are different plans: WHERE pk billed {pq_key_cap!r} and WHERE tag billed '
        f'{pq_nonkey_cap!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
