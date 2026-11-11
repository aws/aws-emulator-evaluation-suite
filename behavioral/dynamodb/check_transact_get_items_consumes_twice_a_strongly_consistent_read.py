"""transact-get-items-consumes-twice-a-strongly-consistent-read."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-get-items-consumes-twice-a-strongly-consistent-read"
GROUP = 'capacity'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A transactional read costs two read units where a strongly consistent GetItem costs one, so
    the multiplier is asserted as a RATIO against the same item rather than as a bare number."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}})
    plain = ddb.get_item(TableName=table, Key={'pk': {'S': 'a'}}, ConsistentRead=True,
                         ReturnConsumedCapacity='TOTAL')['ConsumedCapacity']['CapacityUnits']
    tx = ddb.transact_get_items(
        TransactItems=[{'Get': {'TableName': table, 'Key': {'pk': {'S': 'a'}}}}],
        ReturnConsumedCapacity='TOTAL')['ConsumedCapacity'][0]
    assert plain == 1.0, f'a strongly consistent GetItem of a tiny item costs 1 unit, got {plain}'
    assert tx['CapacityUnits'] == 2 * plain, (
        f"a transactional read costs twice a strong read: expected {2 * plain}, got {tx['CapacityUnits']}"
    )
    assert tx.get('ReadCapacityUnits') == tx['CapacityUnits'], (
        f"TransactGetItems reports the read arm beside the total, got {tx}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
