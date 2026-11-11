"""number-precision-limited-to-38-digits."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "number-precision-limited-to-38-digits"
GROUP = 'representation'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _code(fn) -> tuple[str, str]:
    """The botocore error code and message *fn* raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 38-significant-digit N round-trips exactly; 39 digits (scalar or NS member) is rejected
    with ValidationException and not stored. N is an exact decimal, so a double-based store fails.
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

    # Compared as a string: comparing as a float would itself lose the precision under test.
    at_limit = '9' * 38
    ddb.put_item(TableName=t, Item={'pk': {'S': 'at-limit'}, 'n': {'N': at_limit}})
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'at-limit'}}, ConsistentRead=True).get('Item') or {}
    assert got.get('n') == {'N': at_limit}, (
        f'a 38-digit N must round-trip digit-for-digit, got {got.get("n")!r}'
    )

    over = '9' * 39
    code, message = _code(lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'over'}, 'n': {'N': over}}))
    assert code == ERR_VALIDATION, f'a 39-digit N exceeds supported precision and must be {ERR_VALIDATION}, got {code!r}'
    assert message == "1 validation error detected: Attempting to store more than 38 significant digits in a Number", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    assert 'Item' not in ddb.get_item(TableName=t, Key={'pk': {'S': 'over'}}, ConsistentRead=True), (
        'a number rejected for precision must not be stored'
    )

    # Significant digits, not character count: a 38-significant-digit mantissa is
    # legal even though the decimal point makes the literal 39 characters long.
    fractional = '1.' + '7' * 37
    ddb.put_item(TableName=t, Item={'pk': {'S': 'fractional'}, 'n': {'N': fractional}})
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'fractional'}}, ConsistentRead=True).get('Item') or {}
    assert got.get('n') == {'N': fractional}, (
        f'a 38-significant-digit fractional N must round-trip exactly, got {got.get("n")!r}'
    )

    # A precision overflow inside a set takes the same path as a scalar.
    code, message = _code(lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'in-set'}, 'ns': {'NS': ['1', over]}}))
    assert code == ERR_VALIDATION, (
        f'a 39-digit member of an NS must be {ERR_VALIDATION}, got {code!r}'
    )
    assert message == "1 validation error detected: Attempting to store more than 38 significant digits in a Number", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    # A precision overflow inside a ConditionExpression value is rejected the same way as a
    # stored attribute, not as a failed condition.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'cond-base'}, 'n': {'N': '1'}})
    code, message = _code(lambda: ddb.put_item(
        TableName=t,
        Item={'pk': {'S': 'cond-base'}, 'n': {'N': '2'}},
        ConditionExpression='n <> :v',
        ExpressionAttributeValues={':v': {'N': over}},
    ))
    assert code == ERR_VALIDATION, (
        f'a 39-digit N in a ConditionExpression value exceeds supported precision and must be '
        f'{ERR_VALIDATION} (not ConditionalCheckFailedException), got {code!r}'
    )
    assert message == "1 validation error detected: Attempting to store more than 38 significant digits in a Number", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    unchanged = ddb.get_item(TableName=t, Key={'pk': {'S': 'cond-base'}}, ConsistentRead=True)['Item']
    assert unchanged['n'] == {'N': '1'}, (
        f'a write rejected for precision in its ConditionExpression value must leave the item '
        f'unmodified, got {unchanged["n"]}'
    )

    # A precision overflow in a KEY attribute's value is validated the same way as an ordinary
    # attribute -- before key-schema matching, not a schema mismatch.
    key_t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=key_t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'N'},
        ],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=key_t))
    ddb.get_waiter('table_exists').wait(TableName=key_t, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    code, message = _code(lambda: ddb.put_item(TableName=key_t, Item={'pk': {'S': 'k'}, 'sk': {'N': over}}))
    assert code == ERR_VALIDATION, (
        f'a 39-digit N in a key attribute exceeds supported precision and must be {ERR_VALIDATION}, '
        f'got {code!r}'
    )
    assert message == "1 validation error detected: Attempting to store more than 38 significant digits in a Number", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )
    code, message = _code(lambda: ddb.get_item(TableName=key_t, Key={'pk': {'S': 'k'}, 'sk': {'N': over}}))
    assert code == ERR_VALIDATION, (
        f'GetItem on a 39-digit N key value must also be {ERR_VALIDATION}, got {code!r}'
    )
    assert message == "Attempting to store more than 38 significant digits in a Number", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    # Control: a 38-digit N key value still round-trips in the same table.
    at_limit_key = '9' * 38
    ddb.put_item(TableName=key_t, Item={'pk': {'S': 'k'}, 'sk': {'N': at_limit_key}})
    ok = ddb.get_item(
        TableName=key_t, Key={'pk': {'S': 'k'}, 'sk': {'N': at_limit_key}}, ConsistentRead=True,
    ).get('Item') or {}
    assert ok.get('sk') == {'N': at_limit_key}, (
        f'a 38-digit N key value must still round-trip, got {ok.get("sk")!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
