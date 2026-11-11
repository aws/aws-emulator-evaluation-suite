"""transact-get-items-reports-capacity-per-table-as-a-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-get-items-reports-capacity-per-table-as-a-list"
GROUP = 'capacity'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """A transactional read reports ConsumedCapacity as a LIST with one entry per table, unlike the
    single object GetItem returns -- so a caller cannot read the two the same way."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}})
    tx = ddb.transact_get_items(
        TransactItems=[{'Get': {'TableName': table, 'Key': {'pk': {'S': 'a'}}}}],
        ReturnConsumedCapacity='TOTAL')['ConsumedCapacity']
    plain = ddb.get_item(TableName=table, Key={'pk': {'S': 'a'}},
                         ReturnConsumedCapacity='TOTAL')['ConsumedCapacity']
    assert isinstance(tx, list), f'a transactional read reports a list of per-table entries, got {type(tx).__name__}'
    assert tx[0]['TableName'] == table, f"the entry must name the table, got {tx[0]}"
    assert isinstance(plain, dict), f'GetItem reports a single object, got {type(plain).__name__}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
