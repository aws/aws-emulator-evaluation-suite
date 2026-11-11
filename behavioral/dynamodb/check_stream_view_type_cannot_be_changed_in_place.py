"""stream-view-type-cannot-be-changed-in-place."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stream-view-type-cannot-be-changed-in-place"
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
    """A stream's StreamViewType is fixed once created: changing it requires disabling and recreating,
    so an in-place change is refused and the original view type survives."""
    ddb = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=table, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
                     AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
                     BillingMode='PAY_PER_REQUEST',
                     StreamSpecification={'StreamEnabled': True, 'StreamViewType': 'NEW_IMAGE'})
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    err = _error(
        lambda: ddb.update_table(
            TableName=table,
            StreamSpecification={'StreamEnabled': True, 'StreamViewType': 'NEW_AND_OLD_IMAGES'}),
        'changing StreamViewType in place',
    )
    assert err.get('Code') == 'ValidationException', f"expected ValidationException, got {err.get('Code')}"
    expected = f'Table already has an enabled stream: TableName: {table}'
    assert err.get('Message') == expected, (
        f"expected message {expected!r}, got {err.get('Message')!r}"
    )
    spec = ddb.describe_table(TableName=table)['Table']['StreamSpecification']
    assert spec['StreamViewType'] == 'NEW_IMAGE', (
        f'the original view type must survive the refusal, got {spec}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
