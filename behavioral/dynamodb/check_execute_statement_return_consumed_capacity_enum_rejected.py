"""execute-statement-return-consumed-capacity-enum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-return-consumed-capacity-enum-rejected"
GROUP = 'partiql'
SERVICES = ['dynamodb']
_VALIDATION = (
    'ValidationException',
    "1 validation error detected: Value 'BOGUS' at 'returnConsumedCapacity' failed to satisfy "
    "constraint: Member must satisfy enum value set: [INDEXES, TOTAL, NONE]",
)


def expect_error(fn, code, message):
    """Assert ``fn`` raises exactly (code, message); an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        got_code, got_message = err.get('Code'), err.get('Message')
        assert got_code == code, f'expected error code {code!r}, got {got_code!r}: {got_message!r}'
        assert got_message == message, f'expected error message {message!r}, got {got_message!r}'
        return
    raise AssertionError(f'expected the statement to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An out-of-enum ReturnConsumedCapacity on ExecuteStatement is ValidationException naming
    the member and echoing the value, and the statement writes nothing."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-pqlrcc-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 30})

    expect_error(
        lambda: ddb.execute_statement(
            Statement=f"INSERT INTO \"{table}\" VALUE {{'pk': 'rcc-bogus'}}",
            ReturnConsumedCapacity='BOGUS',
        ),
        *_VALIDATION,
    )
    after = ddb.get_item(TableName=table, Key={'pk': {'S': 'rcc-bogus'}}, ConsistentRead=True)
    assert 'Item' not in after, f'a rejected ExecuteStatement must write nothing, found {after}'

    # Positive control: the identical statement, with a valid ReturnConsumedCapacity, executes.
    ok = ddb.execute_statement(
        Statement=f"INSERT INTO \"{table}\" VALUE {{'pk': 'rcc-ok'}}",
        ReturnConsumedCapacity='TOTAL',
    )
    assert ok.get('Items', []) == [], f'an INSERT must return no items, got {ok.get("Items")!r}'
    written = ddb.get_item(TableName=table, Key={'pk': {'S': 'rcc-ok'}}, ConsistentRead=True)
    assert written.get('Item') == {'pk': {'S': 'rcc-ok'}}, f'expected the write to land, got {written}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
