"""atomic-counter-and-set-add-survive-concurrent-updates."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "atomic-counter-and-set-add-survive-concurrent-updates"
GROUP = 'concurrency'
SERVICES = ['dynamodb']

_WORKERS = 10


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Ten concurrent UpdateItem `ADD` calls on one item leave the counter at exactly 10 and the
    string set holding the ten distinct tokens: ADD is atomic, so no update is lost. Both are
    count invariants that hold under every interleaving.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-atomicadd-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {'pk': {'S': 'COUNTER#1'}}
    ddb.put_item(TableName=table, Item={'pk': {'S': 'COUNTER#1'}, 'counter': {'N': '0'}})

    expected_tokens = {f'worker-{i}' for i in range(_WORKERS)}

    def _bump(i: int):
        try:
            ddb.update_item(
                TableName=table, Key=key,
                UpdateExpression='ADD #c :one, #m :tok',
                ExpressionAttributeNames={'#c': 'counter', '#m': 'members'},
                ExpressionAttributeValues={':one': {'N': '1'},
                                           ':tok': {'SS': [f'worker-{i}']}},
            )
            return None
        except Exception as exc:  # noqa: BLE001 -- reported, never swallowed
            return f'worker-{i}: {type(exc).__name__}: {exc}'

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        errors = [e for e in pool.map(_bump, range(_WORKERS)) if e is not None]

    assert errors == [], f'a concurrent ADD failed outright: {errors!r}'

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)['Item']
    assert item['counter']['N'] == str(_WORKERS), (
        f'lost update on the atomic counter: got {item["counter"]["N"]!r}, expected '
        f'{str(_WORKERS)!r} after {_WORKERS!r} concurrent ADDs'
    )
    members = set(item['members']['SS'])
    assert members == expected_tokens, (
        f'the string set lost members under concurrency: {sorted(expected_tokens - members)!r} '
        f'missing, {sorted(members - expected_tokens)!r} unexpected'
    )
    assert len(item['members']['SS']) == _WORKERS, (
        f'the set has the wrong cardinality: {len(item["members"]["SS"])!r} entries in '
        f'{item["members"]["SS"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
