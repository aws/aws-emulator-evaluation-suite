"""query-never-returns-an-empty-page-with-a-last-evaluated-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-never-returns-an-empty-page-with-a-last-evaluated-key"
GROUP = 'pagination'
SERVICES = ['dynamodb']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """Unlike Scan, Query never returns an empty result set together with a LastEvaluatedKey. The
    Scan arm is asserted in the same check, because the contract is the ASYMMETRY between them."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for i in range(4):
        ddb.put_item(TableName=table, Item={'pk': {'S': f'p{i}'}})
    q = ddb.query(TableName=table, KeyConditionExpression='pk = :v',
                  ExpressionAttributeValues={':v': {'S': 'no-such-key'}})
    assert q['Count'] == 0, f"expected no matches, got {q['Count']}"
    assert 'LastEvaluatedKey' not in q, (
        f"Query must not pair an empty result set with a LastEvaluatedKey, got {q.get('LastEvaluatedKey')}"
    )
    # The contrast arm: a Scan MAY return a truncated page, so a LastEvaluatedKey there is correct
    # and the invariant above is specific to Query rather than a general rule about paging.
    s = ddb.scan(TableName=table, Limit=1)
    assert 'LastEvaluatedKey' in s, (
        'a Scan truncated by Limit must return a LastEvaluatedKey, so the Query rule is an asymmetry'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
