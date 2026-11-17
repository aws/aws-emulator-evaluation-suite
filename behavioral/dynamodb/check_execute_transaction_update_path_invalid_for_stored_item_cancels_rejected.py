"""execute-transaction-update-path-invalid-for-stored-item-cancels-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'execute-transaction-update-path-invalid-for-stored-item-cancels-rejected'
GROUP = 'transactions'
SERVICES = ['dynamodb']
CANCELED = 'TransactionCanceledException'
CANCELED_PREFIX = 'Transaction cancelled, please refer cancellation reasons for specific reasons '
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


def _refusal(fn) -> dict:
    """The error response ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f'expected the call to be refused, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL UPDATE in ExecuteTransaction whose SET path descends through a stored scalar cancels
    the transaction with a ValidationError reason, no Item even with ALL_OLD, and no INSERT applied.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.multiplestatements.transactions.html
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

    stored = {'pk': {'S': 'doc'}, 'm': {'M': {'x': {'N': '1'}}}}
    ddb.put_item(TableName=t, Item=stored)

    def _statements(set_clause: str) -> list:
        return [
            {'Statement': f"INSERT INTO \"{t}\" VALUE {{'pk': 'sibling', 'v': 1}}"},
            {
                'Statement': f"UPDATE \"{t}\" SET {set_clause} WHERE pk = ?",
                'Parameters': [{'S': 'doc'}],
                'ReturnValuesOnConditionCheckFailure': 'ALL_OLD',
            },
        ]

    # m.x holds a number, so m.x.y names a map key inside a scalar.
    err = _refusal(lambda: ddb.execute_transaction(TransactStatements=_statements('m.x.y = 2')))
    assert err['Error']['Code'] == CANCELED, f'expected {CANCELED}, got {err["Error"]!r}'
    expected = CANCELED_PREFIX + '[None, ValidationError]'
    assert err['Error'].get('Message') == expected, (
        f'expected message {expected!r}, got {err["Error"].get("Message")!r}'
    )
    reasons = err.get('CancellationReasons')
    assert reasons == [
        {'Code': 'None'},
        {'Code': 'ValidationError', 'Message': INVALID_PATH},
    ], f'cancellation reasons were {reasons!r}'

    sibling = ddb.get_item(TableName=t, Key={'pk': {'S': 'sibling'}}, ConsistentRead=True)
    assert 'Item' not in sibling, f'the cancelled transaction applied its INSERT: {sibling.get("Item")!r}'
    after = ddb.get_item(TableName=t, Key={'pk': {'S': 'doc'}}, ConsistentRead=True)['Item']
    assert after == stored, f'the cancelled transaction changed the stored item: {after!r}'

    # Positive control: a SET path that fits the stored map commits both statements.
    ddb.execute_transaction(TransactStatements=_statements('m.y = 2'))
    sibling = ddb.get_item(TableName=t, Key={'pk': {'S': 'sibling'}}, ConsistentRead=True).get('Item')
    assert sibling == {'pk': {'S': 'sibling'}, 'v': {'N': '1'}}, f'the committed INSERT read {sibling!r}'
    doc = ddb.get_item(TableName=t, Key={'pk': {'S': 'doc'}}, ConsistentRead=True)['Item']
    assert doc == {'pk': {'S': 'doc'}, 'm': {'M': {'x': {'N': '1'}, 'y': {'N': '2'}}}}, (
        f'the committed UPDATE read back as {doc!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
