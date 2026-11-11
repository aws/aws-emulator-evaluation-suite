"""table-with-sort-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "table-with-sort-key"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTable with composite key (hash + range) is described correctly."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    desc = ddb.describe_table(TableName=table)['Table']
    key_schema = {ks['AttributeName']: ks['KeyType'] for ks in desc['KeySchema']}
    assert key_schema == {'pk': 'HASH', 'sk': 'RANGE'}, f"expected composite key schema pk=HASH/sk=RANGE, got {key_schema!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
