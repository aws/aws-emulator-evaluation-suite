"""partiql-select-and-query-agree-on-one-partition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-select-and-query-agree-on-one-partition"
GROUP = 'partiql'
SERVICES = ['dynamodb']

_IN_PARTITION = 6
_OTHER_PARTITION = 4


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL SELECT on one partition key returns the same items, in the same order, and the same
    ConsumedCapacity as the equivalent Query, so it was planned as a key lookup and not a scan.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlplan-')
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'N'},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for i in range(_IN_PARTITION):
        ddb.put_item(TableName=table, Item={
            'pk': {'S': 'TARGET'}, 'sk': {'N': str(i)}, 'body': {'S': f'target-{i}'},
        })
    # Items outside the target partition make a plan that ignores the predicate cost more.
    for i in range(_OTHER_PARTITION):
        ddb.put_item(TableName=table, Item={
            'pk': {'S': 'OTHER'}, 'sk': {'N': str(i)}, 'body': {'S': f'other-{i}'},
        })

    queried = ddb.query(
        TableName=table,
        KeyConditionExpression='pk = :pk',
        ExpressionAttributeValues={':pk': {'S': 'TARGET'}},
        ConsistentRead=True,
        ReturnConsumedCapacity='TOTAL',
    )
    selected = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE pk = ?',
        Parameters=[{'S': 'TARGET'}],
        ConsistentRead=True,
        ReturnConsumedCapacity='TOTAL',
    )

    assert len(queried['Items']) == _IN_PARTITION, (
        f'the Query control must return the {_IN_PARTITION!r} items in the target partition and '
        f'nothing from the other one, got {len(queried["Items"])!r}: {queried["Items"]!r}'
    )
    assert selected['Items'] == queried['Items'], (
        f'a PartiQL SELECT on one partition key must return the identical items in the identical '
        f'sort-key order as the equivalent Query.\nQuery:  {queried["Items"]!r}\n'
        f'SELECT: {selected["Items"]!r}'
    )

    query_cost = queried['ConsumedCapacity']['CapacityUnits']
    select_cost = selected['ConsumedCapacity']['CapacityUnits']
    assert select_cost == query_cost, (
        f'a partition-key predicate must be planned as a key lookup, so the SELECT costs what the '
        f'Query costs: Query read {query_cost!r} capacity units, SELECT read {select_cost!r}. A '
        f'larger figure means the whole table was read and filtered'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
