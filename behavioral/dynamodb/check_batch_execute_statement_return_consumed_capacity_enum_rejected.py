"""batch-execute-statement-return-consumed-capacity-enum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-execute-statement-return-consumed-capacity-enum-rejected"
GROUP = 'partiql'
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An out-of-enum ReturnConsumedCapacity on BatchExecuteStatement is ValidationException
    naming the member and echoing the value, and the whole batch writes nothing."""
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

    code, message = _error(lambda: ddb.batch_execute_statement(
        Statements=[{'Statement': f'''INSERT INTO "{t}" VALUE {{'pk':'rcc-bogus'}}'''}],
        ReturnConsumedCapacity='BOGUS',
    ))
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}: {message!r}'
    assert message == (
        "1 validation error detected: Value 'BOGUS' at 'returnConsumedCapacity' failed to "
        "satisfy constraint: Member must satisfy enum value set: [INDEXES, TOTAL, NONE]"
    ), f'unexpected message {message!r}'
    after = ddb.get_item(TableName=t, Key={'pk': {'S': 'rcc-bogus'}}, ConsistentRead=True)
    assert 'Item' not in after, f'a rejected BatchExecuteStatement must write nothing, found {after}'

    # Positive control: the identical statement, with a valid ReturnConsumedCapacity, executes.
    ok = ddb.batch_execute_statement(
        Statements=[{'Statement': f'''INSERT INTO "{t}" VALUE {{'pk':'rcc-ok'}}'''}],
        ReturnConsumedCapacity='TOTAL',
    )
    assert 'Error' not in ok['Responses'][0], f'expected the well-formed call to succeed, got {ok}'
    written = ddb.get_item(TableName=t, Key={'pk': {'S': 'rcc-ok'}}, ConsistentRead=True)
    assert written.get('Item') == {'pk': {'S': 'rcc-ok'}}, f'expected the write to land, got {written}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
