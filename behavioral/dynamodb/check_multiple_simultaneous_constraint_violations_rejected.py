"""multiple-simultaneous-constraint-violations-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multiple-simultaneous-constraint-violations-rejected"
GROUP = 'errors'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected the call to be rejected, but it succeeded: {result!r}')


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_active(ctx, ddb, table, cap_s=120.0):
    """Poll DescribeTable until TableStatus is ACTIVE, bounded by the run's own budget."""
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    while True:
        status = ddb.describe_table(TableName=table)['Table']['TableStatus']
        if status == 'ACTIVE':
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f'{table} did not reach ACTIVE in time (last status {status!r})')
        time.sleep(2.0)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Several independent constraint violations at once are refused with one
    ValidationException naming all of them, in a fixed order, exactly once each --
    on scalar members (UpdateItem) and on list elements (CreateTable's GSI/LSI names).
    """
    ddb = ctx.client('dynamodb', config=Config(parameter_validation=False))

    control = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=control,
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'alt', 'AttributeType': 'S'},
        ],
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsi-ctrl',
            'KeySchema': [{'AttributeName': 'alt', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        LocalSecondaryIndexes=[{
            'IndexName': 'lsi-ctrl',
            'KeySchema': [
                {'AttributeName': 'pk', 'KeyType': 'HASH'},
                {'AttributeName': 'alt', 'KeyType': 'RANGE'},
            ],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=control))
    _wait_active(ctx, ddb, control)

    # Positive control: a well-formed CreateTable with legal (>=3 char) GSI/LSI names
    # succeeds in this account, and a well-formed UpdateItem on it succeeds too, so the
    # rejections below are attributable to the broken requests, not to a broken account.
    ddb.put_item(TableName=control, Item={'pk': {'S': 'p'}, 'sk': {'S': 's'}, 'alt': {'S': '1'}})
    ddb.update_item(
        TableName=control,
        Key={'pk': {'S': 'p'}, 'sk': {'S': 's'}},
        UpdateExpression='SET val = :v',
        ExpressionAttributeValues={':v': {'S': 'updated'}},
    )
    got = ddb.get_item(TableName=control, Key={'pk': {'S': 'p'}, 'sk': {'S': 's'}}, ConsistentRead=True)
    assert got['Item']['val'] == {'S': 'updated'}, f'positive control update not visible: {got}'

    code, message = _error(lambda: ddb.update_item(
        TableName='',
        ReturnConsumedCapacity='BOGUS',
        ReturnValues='BOGUS2',
    ))
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}: {message!r}'
    assert message == (
        "4 validation errors detected: Value 'BOGUS' at 'returnConsumedCapacity' failed to "
        "satisfy constraint: Member must satisfy enum value set: [INDEXES, TOTAL, NONE]; "
        "Value '' at 'tableName' failed to satisfy constraint: Member must have length "
        "greater than or equal to 1; Value 'BOGUS2' at 'returnValues' failed to satisfy "
        "constraint: Member must satisfy enum value set: [ALL_NEW, UPDATED_OLD, ALL_OLD, "
        "NONE, UPDATED_NEW]; Value null at 'key' failed to satisfy constraint: Member must "
        "not be null"
    ), f'unexpected message {message!r}'

    broken = ctx.unique_name('sim2real-behav-')
    code, message = _error(lambda: ddb.create_table(
        TableName=broken,
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
        ],
        KeySchema=[
            {'AttributeName': 'pk', 'KeyType': 'HASH'},
            {'AttributeName': 'sk', 'KeyType': 'RANGE'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': 'ab',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        LocalSecondaryIndexes=[{
            'IndexName': 'cd',
            'KeySchema': [
                {'AttributeName': 'pk', 'KeyType': 'HASH'},
                {'AttributeName': 'sk', 'KeyType': 'RANGE'},
            ],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
    ))
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}: {message!r}'
    assert message == (
        "2 validation errors detected: Value 'ab' at "
        "'globalSecondaryIndexes.1.member.indexName' failed to satisfy constraint: Member "
        "must have length greater than or equal to 3; Value 'cd' at "
        "'localSecondaryIndexes.1.member.indexName' failed to satisfy constraint: Member "
        "must have length greater than or equal to 3"
    ), f'unexpected message {message!r}'

    code, _ = _error(lambda: ddb.describe_table(TableName=broken))
    assert code == 'ResourceNotFoundException', (
        f'the rejected CreateTable must not have created {broken!r}, got {code}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
