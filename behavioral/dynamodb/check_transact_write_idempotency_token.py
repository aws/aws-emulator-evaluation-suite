"""transact-write-idempotency-token."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "transact-write-idempotency-token"
GROUP = 'transactions'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactWriteItems with an ADD replayed under the same ClientRequestToken leaves the counter at 1, while a fresh
    token applies the ADD again and moves it to 2.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def counter():
        item = ddb.get_item(TableName=table, Key={'pk': {'S': 'idem-1'}}, ConsistentRead=True).get('Item')
        return None if item is None else item['v']['N']

    increment = [{'Update': {
        'TableName': table,
        'Key': {'pk': {'S': 'idem-1'}},
        'UpdateExpression': 'ADD v :one',
        'ExpressionAttributeValues': {':one': {'N': '1'}},
    }}]

    token = str(uuid.uuid4())
    ddb.transact_write_items(TransactItems=increment, ClientRequestToken=token)
    assert counter() == '1', f'first call must set the counter to 1, got {counter()}'

    ddb.transact_write_items(TransactItems=increment, ClientRequestToken=token)
    assert counter() == '1', (
        f'a replay with the SAME ClientRequestToken must be deduplicated, not re-executed; '
        f'counter is {counter()} (expected 1)'
    )

    ddb.transact_write_items(TransactItems=increment, ClientRequestToken=str(uuid.uuid4()))
    assert counter() == '2', f'a fresh token must apply the ADD again, got {counter()}'

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
