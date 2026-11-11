"""gsi-consistent-read-rejected-while-lsi-consistent-read-succeeds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-consistent-read-rejected-while-lsi-consistent-read-succeeds"
GROUP = 'gsi'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """On one table, a ConsistentRead Query on the LSI returns the item just written, while the same Query on the GSI
    raises ValidationException with the exact message and no items; an eventually consistent GSI Query returns it.
    """
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-idxconsist-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'},
                   {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'},
                              {'AttributeName': 'sk', 'AttributeType': 'S'},
                              {'AttributeName': 'lsi_sk', 'AttributeType': 'S'},
                              {'AttributeName': 'gsi1pk', 'AttributeType': 'S'}],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                          {'AttributeName': 'lsi_sk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsi1',
            'KeySchema': [{'AttributeName': 'gsi1pk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
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

    pk = 'PART#1'
    ddb.put_item(TableName=table, Item={'pk': {'S': pk}, 'sk': {'S': 'S1'},
                                        'lsi_sk': {'S': 'L1'}, 'gsi1pk': {'S': 'A'}})

    # Positive control 1: the LSI is strongly consistent, so this read of the write that
    # immediately preceded it must succeed with NO poll loop.
    lsi_items = ddb.query(TableName=table, IndexName='lsi1', ConsistentRead=True,
                          KeyConditionExpression='pk = :p AND lsi_sk = :l',
                          ExpressionAttributeValues={':p': {'S': pk},
                                                     ':l': {'S': 'L1'}})['Items']
    assert [i['pk']['S'] for i in lsi_items] == [pk], (
        f'the strongly consistent LSI read did not see the write it followed: {lsi_items!r}'
    )

    # Break exactly one thing: the same query shape, against the GLOBAL index.
    try:
        accepted = ddb.query(TableName=table, IndexName='gsi1', ConsistentRead=True,
                             KeyConditionExpression='gsi1pk = :g',
                             ExpressionAttributeValues={':g': {'S': 'A'}})
    except ClientError as exc:
        rejected = exc.response
        accepted = None
    else:
        rejected = None

    assert accepted is None, (
        f'ConsistentRead=True on a global secondary index must be rejected, but the service '
        f'accepted it and returned {accepted.get("Items")!r}'
    )
    code = rejected['Error']['Code']
    message = rejected['Error']['Message']
    assert code == ERR_VALIDATION, (
        f'expected {ERR_VALIDATION!r} for ConsistentRead on a GSI, got {code!r} '
        f'({rejected["Error"].get("Message")!r})'
    )
    assert message == "Consistent reads are not supported on global secondary indexes", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )
    # Effect absent: the rejected query carried no data whatsoever -- not an empty page, no page.
    assert 'Items' not in rejected, (
        f'the rejected consistent GSI query still returned data: {rejected.get("Items")!r}'
    )

    # Positive control 2: the GSI itself works when asked for an eventually consistent read, so
    # the rejection above is about the consistency flag and not about an index that does not exist.
    deadline = time.time() + 120
    gsi_items = []
    while time.time() < deadline:
        gsi_items = ddb.query(TableName=table, IndexName='gsi1',
                              KeyConditionExpression='gsi1pk = :g',
                              ExpressionAttributeValues={':g': {'S': 'A'}})['Items']
        if gsi_items:
            break
        time.sleep(1)
    assert [i['pk']['S'] for i in gsi_items] == [pk], (
        f'the GSI never became queryable at all within 120s, so the rejection is not about '
        f'consistency: {gsi_items!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
