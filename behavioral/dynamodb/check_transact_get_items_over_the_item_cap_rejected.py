"""transact-get-items-over-the-item-cap-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-get-items-over-the-item-cap-rejected"
GROUP = 'transactions'
SERVICES = ['dynamodb']


def _error_code(call, what):
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """TransactGetItems is capped at 100 actions, and the cap is enforced before any read."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    err = _error_code(
        lambda: ddb.transact_get_items(TransactItems=[
            {'Get': {'TableName': table, 'Key': {'pk': {'S': f'k{i}'}}}} for i in range(101)]),
        'a 101-action TransactGetItems',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    message = err.get('Message')
    expected_message = ("1 validation error detected: Value at 'TransactItems' failed to satisfy "
                        "constraint: Member must have length less than or equal to 100")
    assert message == expected_message, f'expected message {expected_message!r}, got {message!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
