"""update-continuous-backups-nonexistent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-continuous-backups-nonexistent"
GROUP = 'errors'
SERVICES = ['dynamodb']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateContinuousBackups on a table that does not exist MUST fail with
    TableNotFoundException (overly-permissive boundary)."""
    ddb = ctx.client('dynamodb')
    name = ctx.unique_name('sim2real-behav-no-such-table-')
    try:
        result = ddb.update_continuous_backups(
            TableName=name,
            PointInTimeRecoverySpecification={'PointInTimeRecoveryEnabled': True},
        )
    except ClientError as exc:
        err = exc.response['Error']
    else:
        raise AssertionError(f'expected TableNotFoundException, but the call succeeded: {result!r}')
    assert err.get('Code') == 'TableNotFoundException', (
        f"expected TableNotFoundException, got {err.get('Code')}"
    )
    expected = f'Table not found: {name}'
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
