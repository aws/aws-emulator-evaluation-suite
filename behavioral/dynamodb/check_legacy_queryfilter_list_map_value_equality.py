"""legacy-queryfilter-list-map-value-equality."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "legacy-queryfilter-list-map-value-equality"
GROUP = 'query'
SERVICES = ['dynamodb']

LIST_VALUE = {'L': [{'S': 'x'}, {'N': '1'}]}
LIST_OTHER = {'L': [{'S': 'x'}, {'N': '2'}]}
MAP_VALUE = {'M': {'a': {'S': 'y'}, 'b': {'N': '1'}}}
MAP_OTHER = {'M': {'a': {'S': 'y'}, 'b': {'N': '2'}}}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy QueryFilter ComparisonOperator EQ on a List or Map AttributeValue narrows a
    partition by deep structural equality, scanning every item under the key condition first.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-qfdoc-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 1, 'MaxAttempts': 60})

    rows = [
        ('s0', LIST_VALUE),
        ('s1', LIST_OTHER),
        ('s2', MAP_VALUE),
        ('s3', MAP_OTHER),
    ]
    for sk, doc in rows:
        ddb.put_item(TableName=table, Item={'pk': {'S': 'p1'}, 'sk': {'S': sk}, 'doc': doc})

    def query_doc_eq(ref_value):
        return ddb.query(
            TableName=table,
            KeyConditions={'pk': {'AttributeValueList': [{'S': 'p1'}], 'ComparisonOperator': 'EQ'}},
            QueryFilter={'doc': {'ComparisonOperator': 'EQ', 'AttributeValueList': [ref_value]}},
            ConsistentRead=True,
        )

    list_resp = query_doc_eq(LIST_VALUE)
    assert list_resp['Count'] == 1, (
        f"legacy QueryFilter EQ on an L value must narrow the 4-item partition to the one "
        f"structurally identical List, got Count={list_resp['Count']!r}"
    )
    assert list_resp['Items'][0]['sk'] == {'S': 's0'}, (
        f"expected the surviving item to be sk=s0, got {list_resp['Items'][0].get('sk')!r}"
    )
    assert list_resp['ScannedCount'] == 4, (
        f"legacy QueryFilter is a post-condition filter -- all 4 items under pk=p1 must be "
        f"scanned before the doc filter narrows it to 1, got ScannedCount={list_resp['ScannedCount']!r}"
    )

    map_resp = query_doc_eq(MAP_VALUE)
    assert map_resp['Count'] == 1, (
        f"legacy QueryFilter EQ on an M value must narrow the 4-item partition to the one "
        f"structurally identical Map, got Count={map_resp['Count']!r}"
    )
    assert map_resp['Items'][0]['sk'] == {'S': 's2'}, (
        f"expected the surviving item to be sk=s2, got {map_resp['Items'][0].get('sk')!r}"
    )
    assert map_resp['ScannedCount'] == 4, (
        f"legacy QueryFilter is a post-condition filter -- all 4 items under pk=p1 must be "
        f"scanned before the doc filter narrows it to 1, got ScannedCount={map_resp['ScannedCount']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
