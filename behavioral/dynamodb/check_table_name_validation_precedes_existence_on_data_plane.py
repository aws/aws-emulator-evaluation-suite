"""table-name-validation-precedes-existence-on-data-plane."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-name-validation-precedes-existence-on-data-plane"
GROUP = 'errors'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
ERR_NOT_FOUND = 'ResourceNotFoundException'


def _code(fn) -> tuple[str, str]:
    """The botocore error code and message *fn* raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A malformed TableName (too short, too long, or outside [a-zA-Z0-9_.-]) is ValidationException on
    every data-plane operation before any existence lookup; well-formed absent names, including a
    3-character one, are ResourceNotFoundException.
    """
    ddb = ctx.client('dynamodb')

    # A real table proves the caller's wiring is good, so a rejection below is
    # attributable to the name rather than to credentials or endpoint.
    good = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=good,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=good))
    ddb.get_waiter('table_exists').wait(TableName=good, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=good, Item={'pk': {'S': 'k'}})
    assert ddb.get_item(TableName=good, Key={'pk': {'S': 'k'}}, ConsistentRead=True).get('Item'), (
        'positive control failed: a legal name on an existing table must read back'
    )

    # Well-formed but absent: this is the error the malformed names must NOT produce.
    absent = ctx.unique_name('sim2real-behav-absent-')
    code, message = _code(lambda: ddb.get_item(TableName=absent, Key={'pk': {'S': 'k'}}))
    assert code == ERR_NOT_FOUND, (
        f'a well-formed name for an absent table must be {ERR_NOT_FOUND}, got {code!r}'
    )
    assert message == 'Requested resource not found', (
        f'a well-formed name for an absent table: got the message {message!r}'
    )

    illegal = {
        'too-short': 'ab',
        'slash': 'bad/name',
        'space': 'bad name',
        'colon': 'bad:name',
        'too-long': 'a' * 256,
    }
    pattern = 'Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+'
    constraint = {
        'too-short': 'Member must have length greater than or equal to 3',
        'slash': pattern,
        'space': pattern,
        'colon': pattern,
        'too-long': 'Member must have length less than or equal to 255',
    }
    for label, name in illegal.items():
        expected_message = (
            f"1 validation error detected: Value '{name}' at 'tableName' failed to satisfy "
            f"constraint: {constraint[label]}"
        )
        ops = {
            'GetItem': lambda n=name: ddb.get_item(TableName=n, Key={'pk': {'S': 'k'}}),
            'PutItem': lambda n=name: ddb.put_item(TableName=n, Item={'pk': {'S': 'k'}}),
            'Query': lambda n=name: ddb.query(
                TableName=n,
                KeyConditionExpression='pk = :p',
                ExpressionAttributeValues={':p': {'S': 'k'}},
            ),
            'DeleteItem': lambda n=name: ddb.delete_item(TableName=n, Key={'pk': {'S': 'k'}}),
        }
        for op, call in ops.items():
            got, message = _code(call)
            assert got == ERR_VALIDATION, (
                f'{op} with a {label} table name must be {ERR_VALIDATION} '
                f'(name validation precedes existence), got {got!r}'
            )
            assert message == expected_message, (
                f'{op} with a {label} table name: expected the message {expected_message!r}, '
                f'got {message!r}'
            )

    # A 3-character name is legal, so the boundary is inclusive and the rule above
    # is a length floor rather than a blanket rejection of short names.
    code, message = _code(lambda: ddb.get_item(TableName='abc', Key={'pk': {'S': 'k'}}))
    assert code == ERR_NOT_FOUND, (
        f'a 3-character name is legal and must reach existence checking, not {code!r}'
    )
    assert message == 'Requested resource not found', (
        f'a 3-character name reaches existence checking: got the message {message!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
