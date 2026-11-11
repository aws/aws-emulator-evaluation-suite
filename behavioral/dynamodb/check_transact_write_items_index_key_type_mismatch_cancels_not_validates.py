"""transact-write-items-index-key-type-mismatch-cancels-not-validates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-write-items-index-key-type-mismatch-cancels-not-validates"
GROUP = 'transactions'
SERVICES = ['dynamodb']


def _raises(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the error IS the assertion
        return exc
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """An index key of the wrong TYPE inside a transaction is not a top-level ValidationException:
    DynamoDB accepts the request and CANCELS it, with reason code ValidationError carrying the
    PutItem-style message. An engine answering a top-level ValidationException diverges."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
        AttributeDefinitions=[
            {'AttributeName': 'pk', 'AttributeType': 'S'},
            {'AttributeName': 'sk', 'AttributeType': 'S'},
            {'AttributeName': 'gpk', 'AttributeType': 'S'},
        ],
        GlobalSecondaryIndexes=[{
            'IndexName': 'gsi1',
            'KeySchema': [{'AttributeName': 'gpk', 'KeyType': 'HASH'}],
            'Projection': {'ProjectionType': 'ALL'},
        }],
        BillingMode='PAY_PER_REQUEST',
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    exc = _raises(
        lambda: ddb.transact_write_items(TransactItems=[
            {'Put': {'TableName': table, 'Item': {'pk': {'S': 'b'}, 'sk': {'S': '1'}, 'gpk': {'N': '9'}}}}]),
        'a transaction whose index key has the wrong type',
    )
    err = getattr(exc, 'response', {}).get('Error', {}) or {}
    reasons = getattr(exc, 'response', {}).get('CancellationReasons') or []
    assert err.get('Code') == 'TransactionCanceledException', (
        f"a wrong-TYPE index key cancels the transaction rather than failing validation up front; "
        f"got {err.get('Code')}"
    )
    expected = ('Transaction cancelled, please refer cancellation reasons for specific reasons '
                '[ValidationError]')
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    assert [r.get('Code') for r in reasons] == ['ValidationError'], (
        f"expected exactly one ValidationError reason, got {[r.get('Code') for r in reasons]}"
    )
    expected_reason = ('One or more parameter values were invalid: Type mismatch for Index Key gpk '
                       'Expected: S Actual: N IndexName: gsi1')
    assert reasons[0].get('Message') == expected_reason, (
        f"expected reason message {expected_reason!r}, got {reasons[0].get('Message')!r}"
    )
    assert ddb.scan(TableName=table, ConsistentRead=True)['Count'] == 0, (
        'a cancelled transaction must write nothing'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
