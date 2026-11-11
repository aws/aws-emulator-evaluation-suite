"""transact-write-exceeds-100-items."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-exceeds-100-items"
GROUP = 'transactions'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'


def _error_code(fn):
    """The error code and message fn() raises; RAISES if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'expected the call to be rejected, but it succeeded: {result!r}')


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactWriteItems with exactly 100 Puts succeeds and writes them; 101 Puts is rejected with
    ValidationException and writes nothing, since a transaction is all-or-nothing."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real-behav', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    at_limit = [
        {'Put': {'TableName': t, 'Item': {'pk': {'S': f'txn-atlimit-{i}'}}}} for i in range(100)
    ]
    ddb.transact_write_items(TransactItems=at_limit)
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'txn-atlimit-0'}}, ConsistentRead=True)
    assert 'Item' in got, 'a transaction at the documented 100-item ceiling must be applied in full'
    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'txn-atlimit-99'}}, ConsistentRead=True)
    assert 'Item' in got, 'a transaction at the documented 100-item ceiling must be applied in full'

    too_many = [
        {'Put': {'TableName': t, 'Item': {'pk': {'S': f'txn-over100-{i}'}}}} for i in range(101)
    ]
    code, message = _error_code(lambda: ddb.transact_write_items(TransactItems=too_many))
    assert code == ERR_VALIDATION, f'expected {ERR_VALIDATION}, got {code}'
    assert message == "1 validation error detected: Value at 'TransactItems' failed to satisfy constraint: Member must have length less than or equal to 100", (
        f"expected AWS's exact ValidationException message, got {message!r}"
    )

    got = ddb.get_item(TableName=t, Key={'pk': {'S': 'txn-over100-0'}}, ConsistentRead=True)
    assert 'Item' not in got, 'a rejected oversized transaction must not have written any item'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
