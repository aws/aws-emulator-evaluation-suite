"""execute-statement-number-precision-in-update-set-and-key-equality."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-number-precision-in-update-set-and-key-equality"
GROUP = 'partiql'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
_OVERFLOW_MESSAGE = 'Attempting to store more than 38 significant digits in a Number'


def _code_and_message(fn) -> tuple[str, str]:
    """The botocore error code and message *fn* raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        return err['Code'], err['Message']
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement enforces the 38-significant-digit N limit for a value assigned in
    UPDATE SET and for one compared in a key equality; a 38-digit N round-trips exactly
    through both positions.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes.Number
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'N'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    at38 = '9' * 38
    over39 = '9' * 39

    def read_control():
        items = ddb.execute_statement(
            Statement=f'SELECT * FROM "{t}" WHERE pk = ?',
            Parameters=[{'N': at38}],
            ConsistentRead=True,
        )['Items']
        assert len(items) == 1, f'expected exactly the control item, got {items!r}'
        return items[0]

    ddb.execute_statement(
        Statement=f'INSERT INTO "{t}" VALUE {{\'pk\':?, \'counter\':?}}',
        Parameters=[{'N': at38}, {'N': '0'}],
    )
    control = read_control()
    assert control['pk'] == {'N': at38}, (
        f'a 38-digit N key must round-trip digit-for-digit, got {control["pk"]!r}'
    )
    assert control['counter'] == {'N': '0'}, f'expected the control counter to be 0, got {control["counter"]!r}'

    # A 39-digit value assigned in UPDATE SET is refused and leaves the attribute untouched.
    code, message = _code_and_message(lambda: ddb.execute_statement(
        Statement=f'UPDATE "{t}" SET counter = ? WHERE pk = ?',
        Parameters=[{'N': over39}, {'N': at38}],
    ))
    assert code == ERR_VALIDATION, f'a 39-digit SET value must be {ERR_VALIDATION}, got {code!r}'
    assert message == _OVERFLOW_MESSAGE, f"expected AWS's exact message, got {message!r}"
    unaffected = read_control()
    assert unaffected['counter'] == {'N': '0'}, (
        f'a rejected SET value must leave the attribute untouched, got {unaffected["counter"]!r}'
    )

    # A 39-digit value compared in the key equality is refused the same way, and writes nothing.
    code, message = _code_and_message(lambda: ddb.execute_statement(
        Statement=f'UPDATE "{t}" SET counter = ? WHERE pk = ?',
        Parameters=[{'N': '1'}, {'N': over39}],
    ))
    assert code == ERR_VALIDATION, f'a 39-digit key equality value must be {ERR_VALIDATION}, got {code!r}'
    assert message == _OVERFLOW_MESSAGE, f"expected AWS's exact message, got {message!r}"
    still_unaffected = read_control()
    assert still_unaffected['counter'] == {'N': '0'}, (
        f'a rejected key equality must change nothing, got {still_unaffected["counter"]!r}'
    )

    # The 38-digit control value round-trips exactly through both the SET and the key equality.
    ddb.execute_statement(
        Statement=f'UPDATE "{t}" SET counter = ? WHERE pk = ?',
        Parameters=[{'N': at38}, {'N': at38}],
    )
    rt = read_control()
    assert rt['counter'] == {'N': at38}, (
        f'a 38-digit SET value must round-trip digit-for-digit, got {rt["counter"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
