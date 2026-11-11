"""reserved-word-needs-expression-attribute-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reserved-word-needs-expression-attribute-name"
GROUP = 'expressions'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A bare reserved word ('status') in a FilterExpression raises ValidationException; the
    identical semantic filter succeeds once the attribute is aliased via ExpressionAttributeNames."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-behav', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={'pk': {'S': 'rw'}, 'status': {'S': 'active'}})

    aliased = ddb.scan(
        TableName=table,
        FilterExpression='#s = :s',
        ExpressionAttributeNames={'#s': 'status'},
        ExpressionAttributeValues={':s': {'S': 'active'}},
        ConsistentRead=True,
    )
    assert aliased['Count'] == 1, f'expected aliased filter to match 1 item, got {aliased["Count"]}'

    try:
        ddb.scan(TableName=table, FilterExpression='status = :s', ExpressionAttributeValues={':s': {'S': 'active'}})
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get('Error', {}).get('Code')
        message = exc.response.get('Error', {}).get('Message')
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION} for bare reserved word, got {code}'
    assert message == "Invalid FilterExpression: Attribute name is a reserved keyword; reserved keyword: status", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
