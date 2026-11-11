"""batch-get-item-over-the-hundred-key-cap-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-item-over-the-hundred-key-cap-rejected"
GROUP = 'batch'
SERVICES = ['dynamodb']


def _error(call, what):
    """The Error dict from a call that MUST be refused."""
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the error IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """BatchGetItem retrieves at most 100 items per call, and the 101st makes the whole request
    invalid rather than returning 100 items with one in UnprocessedKeys."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    err = _error(
        lambda: ddb.batch_get_item(
            RequestItems={table: {'Keys': [{'pk': {'S': f'k{i}'}} for i in range(101)]}}),
        'a BatchGetItem asking for 101 keys',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected_msg = (f"1 validation error detected: Value at 'RequestItems.{table}.member.Keys' failed to "
                    "satisfy constraint: Member must have length less than or equal to 100")
    assert err.get('Message') == expected_msg, f"expected {expected_msg!r}, got {err.get('Message')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
