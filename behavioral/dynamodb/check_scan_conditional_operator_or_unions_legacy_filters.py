"""scan-conditional-operator-or-unions-legacy-filters."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-conditional-operator-or-unions-legacy-filters"
GROUP = 'legacy'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """ConditionalOperator=OR over two legacy ScanFilter entries returns items matching EITHER,
    not their intersection."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'a'}, 'colour': {'S': 'red'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'b'}, 'colour': {'S': 'blue'}})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'c'}, 'colour': {'S': 'green'}})
    res = ddb.scan(TableName=table, ConditionalOperator='OR', ScanFilter={
        'colour': {'ComparisonOperator': 'EQ', 'AttributeValueList': [{'S': 'red'}]},
        'pk': {'ComparisonOperator': 'EQ', 'AttributeValueList': [{'S': 'b'}]},
    })
    got = sorted(i['pk']['S'] for i in res['Items'])
    assert got == ['a', 'b'], f'OR must union the two filters, got {got}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
