"""gsi-query-omits-attributes-the-projection-excludes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-query-omits-attributes-the-projection-excludes"
GROUP = 'gsi'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI with INCLUDE ['kept'] returns only the keys plus 'kept' while the base item holds
    'dropped', and a ProjectionExpression naming 'dropped' on the index is refused
    ValidationException with AWS's message."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-gsiproj-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'sk', 'AttributeType': 'S'},
                              {'AttributeName': 'gsi1pk', 'AttributeType': 'S'}],
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsi1',
            'KeySchema': [{'AttributeName': 'gsi1pk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['kept']},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    deadline = time.time() + 300
    index_status = None
    while time.time() < deadline:
        described = ddb.describe_table(TableName=table)['Table']
        index_status = {i['IndexName']: i['IndexStatus']
                        for i in described.get('GlobalSecondaryIndexes', [])}
        if index_status.get('gsi1') == 'ACTIVE':
            break
        time.sleep(2)
    assert index_status.get('gsi1') == 'ACTIVE', (
        f'gsi1 never became ACTIVE within 300s: {index_status!r}'
    )

    pk = 'CUSTOMER#1'
    ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'sk': {'S': 'S1'},
                                        'gsi1pk': {'S': 'A'}, 'kept': {'S': 'yes'},
                                        'dropped': {'S': 'no'}})

    deadline = time.time() + 120
    items = []
    while time.time() < deadline:
        items = ddb.query(TableName=table, IndexName='gsi1',
                          KeyConditionExpression='gsi1pk = :g',
                          ExpressionAttributeValues={':g': {'S': 'A'}})['Items']
        if items:
            break
        time.sleep(1)
    assert len(items) == 1, f'the index query did not return exactly the one item: {items!r}'
    idx_item = items[0]

    assert set(idx_item) == {'pk', 'sk', 'gsi1pk', 'kept'}, (
        f'the GSI projection returned the wrong attribute set: {sorted(idx_item)!r}, expected '
        f"['gsi1pk', 'kept', 'pk', 'sk']"
    )
    assert 'dropped' not in idx_item, (
        f'a non-projected attribute leaked out of the index: {idx_item!r}'
    )
    assert idx_item['kept']['S'] == 'yes', (
        f'the projected attribute is missing or wrong: {idx_item!r}'
    )

    base = ddb.get_item(TableName=table, Key={'pk': {'S': pk}, 'sk': {'S': 'S1'}},
                        ConsistentRead=True)
    assert base['Item']['dropped']['S'] == 'no', (
        f'the excluded attribute is not on the base item, so the absence asserted above is '
        f'vacuous: {base["Item"]!r}'
    )

    # AWS refuses to be asked for a non-projected attribute rather than silently omitting it.
    try:
        named = ddb.query(TableName=table, IndexName='gsi1',
                          KeyConditionExpression='gsi1pk = :g',
                          ExpressionAttributeValues={':g': {'S': 'A'}},
                          ProjectionExpression='pk, dropped')['Items']
    except ClientError as exc:
        refused = exc.response
        named = None
    else:
        refused = None
    assert named is None, (
        f'a ProjectionExpression naming a non-projected attribute must be refused, but the query '
        f'was accepted and returned {named!r}'
    )
    assert refused['Error']['Code'] == ERR_VALIDATION, (
        f'expected {ERR_VALIDATION!r} when asking a GSI for an attribute it does not project, got '
        f'{refused["Error"]["Code"]!r} ({refused["Error"].get("Message")!r})'
    )
    assert refused['Error']['Message'] == "One or more parameter values were invalid: Global secondary index gsi1 does not project [dropped]", (
        f"expected AWS's exact ValidationException message, got {refused['Error']['Message']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
