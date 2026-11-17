"""concurrent-add-returns-exact-permutation-of-counter-values."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-add-returns-exact-permutation-of-counter-values"
GROUP = 'concurrency'
SERVICES = ['dynamodb']

_RACERS = 20
_KEY = {'pk': {'S': 'counter'}}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """20 concurrent ADD increments on one item each succeed and their UPDATED_NEW values
    are exactly the permutation {1..20}; the item is serialised, never a lost or repeated step.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-addperm-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'counter'}, 'cnt': {'N': '0'}})

    def _inc():
        resp = ddb.update_item(
            TableName=table, Key=_KEY,
            UpdateExpression='ADD cnt :one',
            ExpressionAttributeValues={':one': {'N': '1'}},
            ReturnValues='UPDATED_NEW',
        )
        return int(resp['Attributes']['cnt']['N'])

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        values = sorted(f.result() for f in [pool.submit(_inc) for _ in range(_RACERS)])

    assert values == list(range(1, _RACERS + 1)), (
        f'the {_RACERS} UPDATED_NEW values returned were {values!r}, expected exactly the '
        f'permutation 1..{_RACERS} with no value lost or repeated'
    )

    final = ddb.get_item(TableName=table, Key=_KEY, ConsistentRead=True)['Item']
    assert final['cnt'] == {'N': str(_RACERS)}, (
        f"final consistent read gave cnt={final['cnt']!r}, expected {{'N': {str(_RACERS)!r}}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
