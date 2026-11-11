"""execute-statement-parameter-count-and-key-type-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-parameter-count-and-key-type-mismatch-rejected"
GROUP = 'partiql'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


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
    """ExecuteStatement rejects a Parameters list with fewer entries than the statement's '?'
    placeholders, and a parameter of the wrong type for a key, both as ValidationException
    with nothing written or changed; a matched, correctly typed call is unaffected.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteStatement.html#DDB-ExecuteStatement-request-Parameters
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
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    def read(pk: str):
        return ddb.execute_statement(
            Statement=f'SELECT * FROM "{t}" WHERE pk = ?',
            Parameters=[{'S': pk}],
            ConsistentRead=True,
        )['Items']

    # Positive control: a Parameters list matching the placeholders, with the key's own type.
    ddb.execute_statement(
        Statement=f'INSERT INTO "{t}" VALUE {{\'pk\':?, \'val\':?}}',
        Parameters=[{'S': 'ctrl'}, {'S': 'v0'}],
    )
    control = read('ctrl')
    assert len(control) == 1, f'expected the control item to be written, got {control!r}'
    assert control[0]['val'] == {'S': 'v0'}, f'expected the control val, got {control[0]["val"]!r}'

    # Fewer Parameters entries than the statement's placeholders.
    code, message = _code_and_message(lambda: ddb.execute_statement(
        Statement=f'INSERT INTO "{t}" VALUE {{\'pk\':?, \'val\':?}}',
        Parameters=[{'S': 'fewer'}],
    ))
    assert code == ERR_VALIDATION, f'fewer Parameters than placeholders must be {ERR_VALIDATION}, got {code!r}'
    assert message == "Number of parameters in request and statement don't match.", (
        f"expected AWS's exact message, got {message!r}"
    )
    assert read('fewer') == [], 'a rejected INSERT must not have written an item'

    # A parameter of the wrong type for the key.
    code, message = _code_and_message(lambda: ddb.execute_statement(
        Statement=f'UPDATE "{t}" SET val = ? WHERE pk = ?',
        Parameters=[{'S': 'new'}, {'N': '5'}],
    ))
    assert code == ERR_VALIDATION, f'a wrong-typed key parameter must be {ERR_VALIDATION}, got {code!r}'
    assert message == "Key attribute's data type should match its data type in table's schema: Key pk", (
        f"expected AWS's exact message, got {message!r}"
    )
    unaffected = read('ctrl')
    assert unaffected[0]['val'] == {'S': 'v0'}, (
        f'the control item must be unaffected by the rejected UPDATE, got {unaffected[0]["val"]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
