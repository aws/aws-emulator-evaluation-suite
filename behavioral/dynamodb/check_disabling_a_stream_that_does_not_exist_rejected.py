"""disabling-a-stream-that-does-not-exist-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "disabling-a-stream-that-does-not-exist-rejected"
GROUP = 'streams'
SERVICES = ['dynamodb']


def _error(call, what):
    """The Error dict from a call that MUST be refused."""
    try:
        call()
    except Exception as exc:  # noqa: BLE001 -- the error IS the assertion
        return getattr(exc, 'response', {}).get('Error', {}) or {}
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Disabling a stream on a table that has none is a ValidationException rather than a silent
    success -- the no-op reading is the over-permissive one."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    err = _error(
        lambda: ddb.update_table(TableName=table,
                                 StreamSpecification={'StreamEnabled': False}),
        'disabling a stream on a table with no stream',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected_message = f'Table has no stream to disable: TableName: {table}'
    assert err.get('Message') == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
