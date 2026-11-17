"""partiql-statement-index-key-type-mismatch-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'partiql-statement-index-key-type-mismatch-rejected'
GROUP = 'partiql'
SERVICES = ['dynamodb']
VALIDATION = 'ValidationException'
MISMATCH = ('One or more parameter values were invalid: Type mismatch for Index Key {} '
            'Expected: {} Actual: {} IndexName: {}')
EMPTY_INDEX_KEY = (
    'One or more parameter values are not valid. The update expression attempted to update a secondary '
    'index key to a value that is not supported. The AttributeValue for a key attribute cannot contain '
    'an empty string value.'
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response['Error']['Code'] in not_found:
                return
            raise

    return run_undo


def _refusal(fn) -> dict:
    """The error response ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement refuses an INSERT or UPDATE that gives a GSI or LSI key attribute the wrong type
    or an empty string, writes nothing, and the well-typed statements are served through both indexes.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.html
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'lsk', 'AttributeType': 'N'}, {'AttributeName': 'gpk', 'AttributeType': 'S'},
            {'AttributeName': 'gsk', 'AttributeType': 'N'},
        ],
        LocalSecondaryIndexes=[{
            'IndexName': 'by-l',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'lsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        GlobalSecondaryIndexes=[{
            'IndexName': 'by-g',
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}, {'AttributeName': 'gsk', 'KeyType': 'RANGE'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=t), 'ResourceNotFoundException'))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 300})

    seed = {'pk': {'S': 'p'}, 'sk': {'S': 'seed'}, 'note': {'S': 'kept'}}
    ddb.put_item(TableName=t, Item=seed)

    refused = (
        (f"INSERT INTO \"{t}\" VALUE {{'pk': 'p', 'sk': 'bad', 'gpk': 'g', 'gsk': 'x'}}",
         MISMATCH.format('gsk', 'N', 'S', 'by-g')),
        (f"UPDATE \"{t}\" SET lsk = 'x' WHERE pk = 'p' AND sk = 'seed'",
         MISMATCH.format('lsk', 'N', 'S', 'by-l')),
        (f"UPDATE \"{t}\" SET gpk = 5 WHERE pk = 'p' AND sk = 'seed'",
         MISMATCH.format('gpk', 'S', 'N', 'by-g')),
        (f"UPDATE \"{t}\" SET gpk = '' WHERE pk = 'p' AND sk = 'seed'", EMPTY_INDEX_KEY),
    )
    for statement, message in refused:
        err = _refusal(lambda: ddb.execute_statement(Statement=statement))
        assert err['Error']['Code'] == VALIDATION, f'{statement}: expected {VALIDATION}, got {err["Error"]!r}'
        assert err['Error'].get('Message') == message, (
            f'{statement}: expected {message!r}, got {err["Error"].get("Message")!r}'
        )

    bad = ddb.get_item(TableName=t, Key={'pk': {'S': 'p'}, 'sk': {'S': 'bad'}}, ConsistentRead=True)
    assert 'Item' not in bad, f'a refused INSERT wrote {bad.get("Item")!r}'
    kept = ddb.get_item(TableName=t, Key={'pk': {'S': 'p'}, 'sk': {'S': 'seed'}}, ConsistentRead=True)['Item']
    assert kept == seed, f'a refused UPDATE changed the seeded item: {kept!r}'

    # Positive control: the same statements with well-typed index keys apply and are indexed.
    ddb.execute_statement(Statement=f"INSERT INTO \"{t}\" VALUE {{'pk': 'p', 'sk': 'good', 'gpk': 'g', 'gsk': 5}}")
    ddb.execute_statement(Statement=f"UPDATE \"{t}\" SET lsk = 3 WHERE pk = 'p' AND sk = 'seed'")

    local = ddb.query(
        TableName=t, IndexName='by-l', ConsistentRead=True,
        KeyConditionExpression='pk = :p', ExpressionAttributeValues={':p': {'S': 'p'}},
    )['Items']
    assert local == [{**seed, 'lsk': {'N': '3'}}], f'the LSI held {local!r}'

    deadline = time.monotonic() + 60
    while True:
        # A GSI read is eventually consistent, so poll until the write is indexed.
        glob = ddb.query(
            TableName=t, IndexName='by-g',
            KeyConditionExpression='gpk = :g', ExpressionAttributeValues={':g': {'S': 'g'}},
        )['Items']
        if glob or time.monotonic() > deadline:
            break
        time.sleep(1)
    assert glob == [{'pk': {'S': 'p'}, 'sk': {'S': 'good'}, 'gpk': {'S': 'g'}, 'gsk': {'N': '5'}}], (
        f'the GSI held {glob!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
