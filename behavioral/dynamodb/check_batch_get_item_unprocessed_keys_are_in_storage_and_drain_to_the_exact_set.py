"""batch-get-item-unprocessed-keys-are-in-storage-and-drain-to-the-exact-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-item-unprocessed-keys-are-in-storage-and-drain-to-the-exact-set"
GROUP = 'batch'
SERVICES = ['dynamodb']

_N_ITEMS = 60
_PAYLOAD_BYTES = 380 * 1024


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BatchGetItem of 60 large items comes back partial: UnprocessedKeys is disjoint from the
    returned items and names keys present in storage, and draining it yields exactly the 60, once.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchGetItem.html
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-batchget-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    payload = 'z' * _PAYLOAD_BYTES
    all_keys = [f'k{i:02d}' for i in range(_N_ITEMS)]
    for key in all_keys:
        ddb.put_item(TableName=table, Item={'pk': {'S': key}, 'pad': {'S': payload}})

    first = ddb.batch_get_item(RequestItems={
        table: {'Keys': [{'pk': {'S': k}} for k in all_keys], 'ConsistentRead': True},
    })
    returned = [i['pk']['S'] for i in first['Responses'][table]]
    unprocessed = [k['pk']['S']
                   for k in first.get('UnprocessedKeys', {}).get(table, {}).get('Keys', [])]

    assert returned and unprocessed, (
        f'{_N_ITEMS!r} items of {_PAYLOAD_BYTES!r} bytes cannot fit one BatchGetItem response, so '
        f'the call must come back partial: it returned {len(returned)!r} items and named '
        f'{len(unprocessed)!r} unprocessed keys'
    )
    overlap = sorted(set(returned) & set(unprocessed))
    assert overlap == [], (
        f'a key was both returned and reported unprocessed: {overlap!r}'
    )
    assert all(len(i['pad']['S']) == _PAYLOAD_BYTES for i in first['Responses'][table]), (
        f'the service truncated payloads to fit the response instead of deferring whole items: '
        f'{sorted({len(i["pad"]["S"]) for i in first["Responses"][table]})!r}'
    )

    # UnprocessedKeys is about the response budget, not about existence: the deferred key is in
    # storage right now, which is what makes its absence above a deferral rather than a loss.
    probe = ddb.get_item(TableName=table, Key={'pk': {'S': unprocessed[0]}}, ConsistentRead=True)
    assert probe.get('Item', {}).get('pk', {}).get('S') == unprocessed[0], (
        f'a key reported unprocessed is not in the table at all, so the report was about '
        f'existence rather than the response budget: {unprocessed[0]!r} -> {probe.get("Item")!r}'
    )
    assert len(probe['Item']['pad']['S']) == _PAYLOAD_BYTES, (
        f'the deferred item is present but truncated: {len(probe["Item"]["pad"]["S"])!r} bytes'
    )

    seen = list(returned)
    pending = first.get('UnprocessedKeys') or {}
    rounds = 0
    while pending:
        rounds += 1
        assert rounds <= 30, (
            f'the drain loop did not converge in {rounds!r} rounds; {len(seen)!r} of '
            f'{_N_ITEMS!r} seen'
        )
        page = ddb.batch_get_item(RequestItems=pending)
        seen += [i['pk']['S'] for i in page['Responses'][table]]
        pending = {t: spec for t, spec in (page.get('UnprocessedKeys') or {}).items()
                   if spec.get('Keys')}

    assert sorted(seen) == sorted(all_keys), (
        f'draining UnprocessedKeys did not yield exactly the requested set: symmetric difference '
        f'{sorted(set(seen) ^ set(all_keys))!r}'
    )
    assert len(seen) == _N_ITEMS, (
        f'the drain returned an item more than once: {len(seen) - len(set(seen))!r} duplicates in '
        f'{len(seen)!r} results'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
