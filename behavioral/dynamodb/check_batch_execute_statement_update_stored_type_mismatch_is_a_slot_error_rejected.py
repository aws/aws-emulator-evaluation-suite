"""batch-execute-statement-update-stored-type-mismatch-is-a-slot-error-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'batch-execute-statement-update-stored-type-mismatch-is-a-slot-error-rejected'
GROUP = 'transactions'
SERVICES = ['dynamodb']
WRONG_TYPE = 'An operand in the update expression has an incorrect data type'
INVALID_PATH = 'The document path provided in the update expression is invalid for update'


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement reports an UPDATE that meets a stored value of the wrong type, or a path
    through a stored scalar, as that slot's ValidationError while the other slots still apply.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchExecuteStatement.html
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
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=t), 'ResourceNotFoundException'))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={'Delay': 2, 'MaxAttempts': 150})

    doc = {'pk': {'S': 'doc'}, 's': {'S': 'text'}, 'm': {'M': {'x': {'N': '1'}}}}
    counter = {'pk': {'S': 'counter'}, 'n': {'N': '5'}}
    ddb.put_item(TableName=t, Item=doc)
    ddb.put_item(TableName=t, Item=counter)

    out = ddb.batch_execute_statement(Statements=[
        {'Statement': f'UPDATE "{t}" SET s = s + 1 WHERE pk = ?', 'Parameters': [{'S': 'doc'}]},
        {'Statement': f'UPDATE "{t}" SET n = n + 1 WHERE pk = ?', 'Parameters': [{'S': 'counter'}]},
    ])
    responses = out['Responses']
    assert responses == [
        {'Error': {'Code': 'ValidationError', 'Message': WRONG_TYPE}, 'TableName': t},
        {'TableName': t},
    ], f'slot responses for the stored-type mismatch were {responses!r}'

    out = ddb.batch_execute_statement(Statements=[
        {'Statement': f'UPDATE "{t}" SET m.x.y = 1 WHERE pk = ?', 'Parameters': [{'S': 'doc'}]},
        {'Statement': f'UPDATE "{t}" SET n = n + 1 WHERE pk = ?', 'Parameters': [{'S': 'counter'}]},
    ])
    responses = out['Responses']
    assert responses == [
        {'Error': {'Code': 'ValidationError', 'Message': INVALID_PATH}, 'TableName': t},
        {'TableName': t},
    ], f'slot responses for the path through a scalar were {responses!r}'

    after = ddb.get_item(TableName=t, Key={'pk': {'S': 'doc'}}, ConsistentRead=True)['Item']
    assert after == doc, f'a refused slot changed its item: {after!r}'
    # The sibling slot is the positive control: it applied once per batch.
    n = ddb.get_item(TableName=t, Key={'pk': {'S': 'counter'}}, ConsistentRead=True)['Item']
    assert n == {'pk': {'S': 'counter'}, 'n': {'N': '7'}}, f'the sibling slot read back as {n!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
