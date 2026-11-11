"""transactional-read-costs-double-a-strongly-consistent-read."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transactional-read-costs-double-a-strongly-consistent-read"
GROUP = 'transactions'
SERVICES = ['dynamodb']

_ITEMS = 4
_PAYLOAD = 'z' * 900             # well under the 4 KB read-unit boundary


def _total(consumed, table):
    """Sum CapacityUnits across a ConsumedCapacity list, asserting each entry names the table.

    Hard-subscripted: a `.get(..., [])` would supply exactly the value this check detects.
    """
    assert isinstance(consumed, list) and consumed, (
        f'BatchGetItem/TransactGetItems must report ConsumedCapacity as a non-empty list, one entry '
        f'per table, got {consumed!r}'
    )
    for entry in consumed:
        assert entry['TableName'] == table, (
            f'every ConsumedCapacity entry must name the table it charges, got '
            f'{entry.get("TableName")!r} expected {table!r}'
        )
    return sum(entry['CapacityUnits'] for entry in consumed)


def _item_map(items):
    """{pk: full item} for a list of returned items, so three reads can be compared exactly."""
    return {i['pk']['S']: i for i in items}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Eventual BatchGetItem, strong BatchGetItem and TransactGetItems bill 1x, 2x and 4x one unit
    over the same keys, while all three return identical items.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-txnread-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real:managed', 'Value': 'true'},
              {'Key': 'sim2real:check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    keys = [f'K#{i:02d}' for i in range(_ITEMS)]
    written = {}
    for i, pk in enumerate(keys):
        item = {'pk': {'S': pk}, 'v': {'N': str(i)}, 'payload': {'S': _PAYLOAD}}
        written[pk] = item
        ddb.put_item(TableName=table, Item=item)

    key_list = [{'pk': {'S': pk}} for pk in keys]

    eventual = ddb.batch_get_item(
        RequestItems={table: {'Keys': key_list, 'ConsistentRead': False}},
        ReturnConsumedCapacity='TOTAL',
    )
    strong = ddb.batch_get_item(
        RequestItems={table: {'Keys': key_list, 'ConsistentRead': True}},
        ReturnConsumedCapacity='TOTAL',
    )
    transactional = ddb.transact_get_items(
        TransactItems=[{'Get': {'TableName': table, 'Key': k}} for k in key_list],
        ReturnConsumedCapacity='TOTAL',
    )

    # All three must have really read everything, or the numbers below are measuring less work.
    for label, resp in (('eventual BatchGetItem', eventual), ('strong BatchGetItem', strong)):
        residue = resp.get('UnprocessedKeys') or {}
        assert not residue, (
            f'{label} left UnprocessedKeys {residue!r}; its capacity number therefore covers fewer '
            f'than the {_ITEMS!r} items and cannot be compared'
        )
    eventual_items = _item_map(eventual['Responses'][table])
    strong_items = _item_map(strong['Responses'][table])
    txn_items = _item_map([r['Item'] for r in transactional['Responses']])
    for label, got in (('eventual BatchGetItem', eventual_items),
                       ('strong BatchGetItem', strong_items),
                       ('TransactGetItems', txn_items)):
        assert got == written, (
            f'{label} must return all {_ITEMS!r} items byte-identically -- a cheaper capacity number '
            f'earned by returning less data is not the property under test. Missing '
            f'{sorted(set(written) - set(got))!r}, differing '
            f'{sorted(k for k in set(written) & set(got) if got[k] != written[k])!r}'
        )

    eventual_cap = _total(eventual['ConsumedCapacity'], table)
    strong_cap = _total(strong['ConsumedCapacity'], table)
    txn_cap = _total(transactional['ConsumedCapacity'], table)

    assert eventual_cap > 0, (
        f'an eventually consistent BatchGetItem of {_ITEMS!r} items must bill something, got '
        f'{eventual_cap!r} -- with a zero baseline every ratio below is vacuous'
    )
    assert strong_cap == 2 * eventual_cap, (
        f'a strongly consistent read of an item up to 4 KB is one read unit and an eventually '
        f'consistent read is one half, so over the identical {_ITEMS!r} keys the strong read must '
        f'bill exactly twice the eventual one: strong {strong_cap!r} vs eventual {eventual_cap!r} '
        f'(expected {2 * eventual_cap!r})'
    )
    assert txn_cap == 2 * strong_cap, (
        f'a transactional read of an item up to 4 KB is TWO read units, so TransactGetItems over the '
        f'identical {_ITEMS!r} keys must bill exactly twice the strongly consistent BatchGetItem: '
        f'transactional {txn_cap!r} vs strong {strong_cap!r} (expected {2 * strong_cap!r}); a target '
        f'that implements the transactional read as a locked batch reports {strong_cap!r}'
    )
    # BatchGetItem rounds EACH item up to 4 KB and then totals, so a sub-4 KB item is exactly one
    # strong read unit.
    assert strong_cap == float(_ITEMS), (
        f'BatchGetItem rounds each item up to the next 4 KB boundary and then totals, so {_ITEMS!r} '
        f'sub-4 KB items must bill exactly {float(_ITEMS)!r} strongly consistent read units, got '
        f'{strong_cap!r}'
    )

    # The single-item form must obey the same rule, so the ratio is not an artefact of batching.
    single_strong = ddb.get_item(
        TableName=table, Key=key_list[0], ConsistentRead=True,
        ReturnConsumedCapacity='TOTAL',
    )['ConsumedCapacity']['CapacityUnits']
    single_txn = _total(ddb.transact_get_items(
        TransactItems=[{'Get': {'TableName': table, 'Key': key_list[0]}}],
        ReturnConsumedCapacity='TOTAL',
    )['ConsumedCapacity'], table)
    assert single_txn == 2 * single_strong, (
        f'the 2x transactional factor must hold for a single-item read too, not only in a batch: '
        f'TransactGetItems billed {single_txn!r} against GetItem(ConsistentRead=True) '
        f'{single_strong!r} (expected {2 * single_strong!r})'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
