"""table-arn-addresses-a-table-wherever-a-name-does."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-arn-addresses-a-table-wherever-a-name-does"
GROUP = 'access_path'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error_code(fn, what: str) -> tuple[str, str]:
    """The AWS error code and message `fn` raises; an unexpected success fails loudly."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A table's ARN and bare name address one table in TableName: writes by either spelling are read
    by the other, and Query, DeleteItem and DescribeTable resolve the ARN; malformed names and ARNs
    are still ValidationException and leave the table untouched.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-arn-')
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
    assert arn.endswith(f':table/{t}'), (
        f'setup: the ARN must name this table so the substitutions below are meaningful, got {arn!r}'
    )

    # --- write by name, read by ARN ---
    ddb.put_item(TableName=t, Item={'pk': {'S': 'by-name'}, 'd': {'S': 'written-by-name'}})
    via_arn = ddb.get_item(TableName=arn, Key={'pk': {'S': 'by-name'}}, ConsistentRead=True)
    assert via_arn.get('Item') == {'pk': {'S': 'by-name'}, 'd': {'S': 'written-by-name'}}, (
        f'an item written by bare name must be readable by ARN -- the two spellings address one '
        f'table, not two stores. Got {via_arn.get("Item")!r}'
    )

    # --- write by ARN, read by name ---
    ddb.put_item(TableName=arn, Item={'pk': {'S': 'by-arn'}, 'd': {'S': 'written-by-arn'}})
    via_name = ddb.get_item(TableName=t, Key={'pk': {'S': 'by-arn'}}, ConsistentRead=True)
    assert via_name.get('Item') == {'pk': {'S': 'by-arn'}, 'd': {'S': 'written-by-arn'}}, (
        f'an item written by ARN must be readable by bare name, got {via_name.get("Item")!r}'
    )

    # --- Query, DescribeTable and DeleteItem accept the ARN too ---
    q = ddb.query(TableName=arn, KeyConditionExpression='pk = :p',
                  ExpressionAttributeValues={':p': {'S': 'by-arn'}}, ConsistentRead=True)
    assert q['Count'] == 1 and q['Items'][0]['d'] == {'S': 'written-by-arn'}, (
        f'Query must accept the ARN and return the item, got {q!r}'
    )
    desc = ddb.describe_table(TableName=arn)['Table']
    assert desc['TableName'] == t and desc['TableArn'] == arn, (
        f'DescribeTable by ARN must resolve to the same table, got TableName={desc["TableName"]!r} '
        f'TableArn={desc["TableArn"]!r}'
    )
    ddb.delete_item(TableName=arn, Key={'pk': {'S': 'by-name'}})
    gone = ddb.get_item(TableName=t, Key={'pk': {'S': 'by-name'}}, ConsistentRead=True)
    assert 'Item' not in gone, (
        f'a DeleteItem addressed by ARN must remove the item the bare name reads, got '
        f'{gone.get("Item")!r}'
    )

    # --- the grammar is not loosened by accepting the ARN spelling ---
    segments = arn.split(':')
    malformed = {
        "a bare name containing '/'": f'{t}/x',
        'an ARN with an empty vendor segment':
            ':'.join([segments[0], segments[1], '', segments[3], segments[4], segments[5]]),
        'an ARN naming a different resource type': arn.replace(':table/', ':stream/'),
    }
    constraint = {
        "a bare name containing '/'":
            'Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+',
        'an ARN with an empty vendor segment': (
            "Valid ARN format is 'arn:<awsPartition>:<vendor>:<region>:<subscriber>:"
            "resourceType/resourceName', where Resource name must have length less than or equal "
            'to 255, Resource name must have length greater than or equal to 3, Resource name must '
            'satisfy regular expression pattern: [a-zA-Z0-9_.-]+'
        ),
        'an ARN naming a different resource type': 'Invalid resource type',
    }
    for why, bad in malformed.items():
        expected_message = (
            f"1 validation error detected: Value '{bad}' at 'tableName' failed to satisfy "
            f"constraint: {constraint[why]}"
        )
        code, message = _error_code(
            lambda bad=bad: ddb.get_item(TableName=bad, Key={'pk': {'S': 'by-arn'}}),
            f'GetItem addressed by {why}')
        assert code == ERR_VALIDATION, (
            f'{why} is not a legal TableName and must be refused {ERR_VALIDATION} rather than '
            f'resolved leniently, got {code!r}'
        )
        assert message == expected_message, (
            f'GetItem addressed by {why}: expected the message {expected_message!r}, got {message!r}'
        )
        code, message = _error_code(
            lambda bad=bad: ddb.put_item(TableName=bad, Item={'pk': {'S': 'smuggled'}}),
            f'PutItem addressed by {why}')
        assert code == ERR_VALIDATION, (
            f'{why} must be refused {ERR_VALIDATION} on a write too, got {code!r}'
        )
        assert message == expected_message, (
            f'PutItem addressed by {why}: expected the message {expected_message!r}, got {message!r}'
        )

    # --- effect absent: no refused write reached the table under either spelling ---
    for spelling, name in (('bare name', t), ('ARN', arn)):
        smuggled = ddb.get_item(TableName=name, Key={'pk': {'S': 'smuggled'}}, ConsistentRead=True)
        assert 'Item' not in smuggled, (
            f'a write refused for a malformed identifier must not land, but reading by {spelling} '
            f'found {smuggled.get("Item")!r}'
        )
        scanned = ddb.scan(TableName=name, ConsistentRead=True, Select='COUNT')
        assert scanned['Count'] == 1, (
            f'only the surviving by-arn item may remain; scanning by {spelling} counted '
            f'{scanned["Count"]!r}'
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
