"""update-table-on-a-missing-table-is-resource-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-table-on-a-missing-table-is-resource-not-found"
GROUP = 'table_lifecycle'
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
    """UpdateTable against a well-formed name that does not exist is ResourceNotFoundException, not a
    validation error -- the name was fine, the table was not there."""
    ddb = ctx.client('dynamodb')
    absent = ctx.unique_name('sim2real-behav-absent-')
    err = _error(
        lambda: ddb.update_table(TableName=absent, BillingMode='PAY_PER_REQUEST'),
        'UpdateTable on a table that does not exist',
    )
    assert err.get('Code') == 'ResourceNotFoundException', (
        f"expected ResourceNotFoundException, got {err.get('Code')}"
    )
    expected = f'Requested resource not found: Table: {absent} not found'
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
