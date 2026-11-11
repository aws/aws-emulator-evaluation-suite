"""table-name-charset-and-length-validated-before-existence-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-name-charset-and-length-validated-before-existence-rejected"
GROUP = 'errors'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
ERR_NOT_FOUND = 'ResourceNotFoundException'


def _error_code(fn, what: str) -> tuple[str, str]:
    """The AWS error code and message `fn` raises; an unexpected success fails loudly."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TableName outside length 3..255 over [a-zA-Z0-9_.-] is ValidationException on GetItem, PutItem,
    Query and DeleteItem before any lookup, while legal absent names (including both length bounds)
    are ResourceNotFoundException, and no refused write creates a table.
    """
    ddb = ctx.client('dynamodb')
    real = ctx.unique_name('sim2real-behav-nm-')
    ddb.create_table(
        TableName=real,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=real))
    ddb.get_waiter('table_exists').wait(TableName=real, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Positive control: all four operations work against a well-formed name that DOES exist, so a
    # target that refuses every request cannot pass the rejections below.
    ddb.put_item(TableName=real, Item={'pk': {'S': 'ctl'}})
    got = ddb.get_item(TableName=real, Key={'pk': {'S': 'ctl'}}, ConsistentRead=True)
    assert got.get('Item') == {'pk': {'S': 'ctl'}}, (
        f'positive control: PutItem/GetItem on a legal, existing name must round-trip, got '
        f'{got.get("Item")!r}'
    )
    q = ddb.query(TableName=real, KeyConditionExpression='pk = :p',
                  ExpressionAttributeValues={':p': {'S': 'ctl'}}, ConsistentRead=True)
    assert q['Count'] == 1, f'positive control: Query must find the control item, got {q!r}'
    ddb.delete_item(TableName=real, Key={'pk': {'S': 'ctl'}})
    gone = ddb.get_item(TableName=real, Key={'pk': {'S': 'ctl'}}, ConsistentRead=True)
    assert 'Item' not in gone, (
        f'positive control: DeleteItem on a legal, existing name must remove the item, got '
        f'{gone.get("Item")!r}'
    )

    def _ops(name):
        return {
            'GetItem': lambda: ddb.get_item(TableName=name, Key={'pk': {'S': 'x'}}),
            'PutItem': lambda: ddb.put_item(TableName=name, Item={'pk': {'S': 'x'}}),
            'Query': lambda: ddb.query(TableName=name, KeyConditionExpression='pk = :p',
                                       ExpressionAttributeValues={':p': {'S': 'x'}}),
            'DeleteItem': lambda: ddb.delete_item(TableName=name, Key={'pk': {'S': 'x'}}),
        }

    # --- names the grammar forbids: rejected before the table is ever looked up ---
    illegal = {
        'two characters (below the 3-character floor)': 'ab',
        "a '/' outside [a-zA-Z0-9_.-]": 'a/b',
        'a space outside [a-zA-Z0-9_.-]': 'a b',
        "a ':' outside [a-zA-Z0-9_.-]": 'a:b',
        '256 characters (above the 255-character ceiling)': 'a' * 256,
    }
    pattern = 'Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+'
    constraint = {
        'two characters (below the 3-character floor)':
            'Member must have length greater than or equal to 3',
        "a '/' outside [a-zA-Z0-9_.-]": pattern,
        'a space outside [a-zA-Z0-9_.-]': pattern,
        "a ':' outside [a-zA-Z0-9_.-]": pattern,
        '256 characters (above the 255-character ceiling)':
            'Member must have length less than or equal to 255',
    }
    for why, name in illegal.items():
        expected_message = (
            f"1 validation error detected: Value '{name}' at 'tableName' failed to satisfy "
            f"constraint: {constraint[why]}"
        )
        for op, call in _ops(name).items():
            code, message = _error_code(call, f'{op} with a name that is {why}')
            assert code == ERR_VALIDATION, (
                f'{op} with a TableName that is {why} must be refused {ERR_VALIDATION} before the '
                f'table lookup, got {code!r}'
            )
            assert message == expected_message, (
                f'{op} with a TableName that is {why}: expected the message '
                f'{expected_message!r}, got {message!r}'
            )

    # --- names the grammar allows but nothing answers to: they reach the lookup ---
    suffix = uuid.uuid4().hex[:8]
    legal_absent = {
        'the inclusive 3-character floor': 'a' + suffix[:2],
        'the inclusive 255-character ceiling': ('sim2real-behav-ghost-' + suffix).ljust(255, 'z'),
        'a dotted/underscored name using every allowed class': f'sim2real.behav_ghost-{suffix}',
    }
    for why, name in legal_absent.items():
        assert 3 <= len(name) <= 255, f'test data error: {name!r} is not within the legal length'
        for op, call in _ops(name).items():
            code, message2 = _error_code(call, f'{op} with a legal absent name at {why}')
            assert code == ERR_NOT_FOUND, (
                f'{op} with a TableName at {why} satisfies the grammar and must therefore reach '
                f'existence checking and be refused {ERR_NOT_FOUND}, got {code!r}'
            )
            assert message2 == "Requested resource not found", (
                f"expected AWS's exact ResourceNotFoundException message, got {message2!r}"
            )

    # --- effect absent: none of the refused PutItems brought a table into being ---
    live = set()
    paginator = ddb.get_paginator('list_tables')
    for page in paginator.paginate():
        live.update(page.get('TableNames', []))
    for name in list(illegal.values()) + list(legal_absent.values()):
        assert name not in live, (
            f'a refused PutItem must not create the table it addressed, but {name!r} is present in '
            f'ListTables'
        )
    for why, name in legal_absent.items():
        code, message2 = _error_code(lambda name=name: ddb.describe_table(TableName=name),
                           f'DescribeTable on the ghost at {why}')
        assert code == ERR_NOT_FOUND, (
            f'the ghost table at {why} must still not exist after the refused writes, got {code!r}'
        )
        assert message2 == f"Requested resource not found: Table: {name} not found", (
            f"expected AWS's exact ResourceNotFoundException message, got {message2!r}"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
