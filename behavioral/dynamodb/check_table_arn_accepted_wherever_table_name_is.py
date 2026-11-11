"""table-arn-accepted-wherever-table-name-is."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-arn-accepted-wherever-table-name-is"
GROUP = 'access_path'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _code(fn) -> tuple[str, str]:
    """The botocore error code and message *fn* raises.

    An unexpected SUCCESS raises rather than returning None: a responder that ACCEPTS a request real
    AWS refuses is the strongest signal this check can produce.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TableName accepts a full table ARN as well as a bare name for the same table: items written through one form
    read back through the other, while a slashed name and malformed ARNs raise ValidationException with the exact
    message.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    arn = ddb.describe_table(TableName=t)['Table']['TableArn']
    assert arn.endswith(f'table/{t}'), f'the described ARN must name this table, got {arn!r}'
    assert ':' in arn and '/' in arn, (
        f'a table ARN contains characters a bare table name may not, which is the point of this check: {arn!r}'
    )

    # Write by bare name, read by ARN.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'by-name'}, 'v': {'S': 'written-by-name'}})
    got = ddb.get_item(TableName=arn, Key={'pk': {'S': 'by-name'}}, ConsistentRead=True).get('Item') or {}
    assert got.get('v') == {'S': 'written-by-name'}, (
        f'an item written by bare name must be readable by ARN, got {got!r}'
    )

    # Write by ARN, read by bare name.
    ddb.put_item(TableName=arn, Item={'pk': {'S': 'by-arn'}, 'v': {'S': 'written-by-arn'}})
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'by-arn'}}, ConsistentRead=True).get('Item') or {}
    assert got.get('v') == {'S': 'written-by-arn'}, (
        f'an item written by ARN must be readable by bare name, got {got!r}'
    )

    # Query and DescribeTable accept the ARN form too.
    rows = ddb.query(
        TableName=arn,
        KeyConditionExpression='pk = :p',
        ExpressionAttributeValues={':p': {'S': 'by-arn'}},
    ).get('Items') or []
    assert len(rows) == 1, f'Query by ARN must find the item, got {len(rows)} rows'
    assert ddb.describe_table(TableName=arn)['Table']['TableName'] == t, (
        'DescribeTable by ARN must describe the same table and report its bare name'
    )

    # Accepting an ARN does not mean accepting arbitrary punctuation: a string that
    # is neither a legal bare name nor a well-formed table ARN is still rejected.
    pattern = 'Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+'
    arn_format = (
        "Valid ARN format is 'arn:<awsPartition>:<vendor>:<region>:<subscriber>:"
        "resourceType/resourceName', where Resource name must have length less than or equal to "
        '255, Resource name must have length greater than or equal to 3, Resource name must '
        'satisfy regular expression pattern: [a-zA-Z0-9_.-]+'
    )
    for label, bad, constraint in (
        ('bare name with a slash', 'not/a/name', pattern),
        ('ARN with an empty service', arn.replace(':dynamodb:', '::', 1), arn_format),
        ('ARN naming a different resource type', arn.replace('table/', 'dummy/', 1),
         'Invalid resource type'),
    ):
        code, message = _code(lambda b=bad: ddb.get_item(TableName=b, Key={'pk': {'S': 'by-arn'}}))
        assert code == ERR_VALIDATION, (
            f'{label} is neither a legal name nor a well-formed table ARN and must be '
            f'{ERR_VALIDATION}, got {code!r} for {bad!r}'
        )
        expected_message = (
            f"1 validation error detected: Value '{bad}' at 'tableName' failed to satisfy "
            f"constraint: {constraint}"
        )
        assert message == expected_message, (
            f'{label}: expected the message {expected_message!r}, got {message!r}'
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
