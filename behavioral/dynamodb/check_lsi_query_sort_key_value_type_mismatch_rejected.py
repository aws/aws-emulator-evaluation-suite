"""lsi-query-sort-key-value-type-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lsi-query-sort-key-value-type-mismatch-rejected"
GROUP = 'lsi'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
_SCHEMA_TYPE_MISMATCH = (
    "One or more parameter values were invalid: Condition parameter type does not match schema type"
)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Querying an LSI with a key-condition value whose type (S) mismatches the LSI sort key's
    declared type (N) is rejected with ValidationException; the correctly typed value finds the
    item."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'N'},
        ],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi1',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={'pk': {'S': 'item'}, 'sk': {'S': '1'}, 'lsk': {'N': '5'}})

    try:
        result = ddb.query(TableName=table, IndexName='lsi1', KeyConditionExpression='pk = :pk AND lsk = :lsk',
                           ExpressionAttributeValues={':pk': {'S': 'item'}, ':lsk': {'S': '5'}})
    except ClientError as exc:
        code = exc.response['Error']['Code']
        message = exc.response['Error'].get('Message')
    else:
        raise AssertionError(
            f'a Query whose LSI sort-key value type (S) mismatches the schema type (N) must be '
            f'rejected, but it SUCCEEDED and returned {result!r}'
        )
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}'
    assert message == _SCHEMA_TYPE_MISMATCH, (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    control = ddb.query(TableName=table, IndexName='lsi1', KeyConditionExpression='pk = :pk AND lsk = :lsk',
                        ExpressionAttributeValues={':pk': {'S': 'item'}, ':lsk': {'N': '5'}},
                        ConsistentRead=True)
    assert control['Count'] == 1, (
        f"the correctly typed control query must find the item, got {control['Count']} items"
    )
    assert control['Items'][0]['sk']['S'] == '1', (
        f"the control resolved sk={control['Items'][0]['sk']['S']!r}, expected '1'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
