"""transact-write-items-consumes-twice-a-plain-write."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-write-items-consumes-twice-a-plain-write"
GROUP = 'capacity'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A transactional write costs two write units per KB -- one to prepare, one to commit -- where
    PutItem costs one. Asserted as a ratio on a table with NO index, so no index arm confounds it."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    plain = ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}},
                         ReturnConsumedCapacity='TOTAL')['ConsumedCapacity']['CapacityUnits']
    tx = ddb.transact_write_items(
        TransactItems=[{'Put': {'TableName': table, 'Item': {'pk': {'S': 'b'}}}}],
        ReturnConsumedCapacity='TOTAL')['ConsumedCapacity'][0]
    assert plain == 1.0, f'a PutItem of a tiny item costs 1 write unit, got {plain}'
    assert tx['CapacityUnits'] == 2 * plain, (
        f"a transactional write costs twice a plain write: expected {2 * plain}, got {tx['CapacityUnits']}"
    )
    assert tx.get('WriteCapacityUnits') == tx['CapacityUnits'], (
        f"TransactWriteItems reports the write arm beside the total, got {tx}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
