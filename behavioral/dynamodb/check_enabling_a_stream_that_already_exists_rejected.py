"""enabling-a-stream-that-already-exists-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "enabling-a-stream-that-already-exists-rejected"
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
    """Enabling a stream on a table that already has one is a ValidationException, and the existing
    stream is left in place with its descriptor unchanged."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST',
                     StreamSpecification={'StreamEnabled': True, 'StreamViewType': 'NEW_IMAGE'})
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    before = ddb.describe_table(TableName=table)['Table']['LatestStreamArn']
    err = _error(
        lambda: ddb.update_table(
            TableName=table,
            StreamSpecification={'StreamEnabled': True, 'StreamViewType': 'NEW_IMAGE'}),
        'enabling a stream that is already enabled',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected_message = f'Table already has an enabled stream: TableName: {table}'
    assert err.get('Message') == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )
    after = ddb.describe_table(TableName=table)['Table']['LatestStreamArn']
    assert after == before, f'the existing stream must be untouched: {before} -> {after}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
