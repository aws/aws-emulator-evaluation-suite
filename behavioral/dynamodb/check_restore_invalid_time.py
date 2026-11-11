"""restore-invalid-time."""
from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-invalid-time"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']
ERR_INVALID_RESTORE_TIME = 'InvalidRestoreTimeException'


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message', '')
    raise AssertionError(f'expected the call to be rejected, but it SUCCEEDED and returned {result!r}')


def _delete_table_if_exists(ddb, name, timeout_s=1800.0):
    """Delete a table, waiting out a restore still writing it (ResourceInUseException)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=name)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ResourceNotFoundException':
                return
            if code != 'ResourceInUseException' or time.monotonic() > deadline:
                raise
            time.sleep(15.0)


def _describe_status_or_none(ddb, name):
    try:
        return ddb.describe_table(TableName=name)['Table']['TableStatus']
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _enable_pitr(ctx, ddb, name):
    def _try():
        try:
            ddb.update_continuous_backups(
                TableName=name,
                PointInTimeRecoverySpecification={'PointInTimeRecoveryEnabled': True},
            )
            return True
        except ClientError as exc:
            if exc.response['Error']['Code'] != 'ContinuousBackupsUnavailableException':
                raise
            return False

    _poll_until(_try, lambda ok: ok, timeout_s=120, interval_s=3.0, description='PITR enable available')
    _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=name)['ContinuousBackupsDescription'][
            'PointInTimeRecoveryDescription'
        ].get('PointInTimeRecoveryStatus'),
        lambda s: s == 'ENABLED',
        timeout_s=120,
        interval_s=2.0,
        description='PITR ENABLED',
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreTableToPointInTime with a RestoreDateTime in the future raises InvalidRestoreTimeException whose
    message bounds the restorable window for the table, and creates no table, while the same call with
    UseLatestRestorableTime is accepted.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    _enable_pitr(ctx, ddb, t)

    # Positive control: the same call shape with a valid restore time must be accepted, and an
    # independent read must show the target actually exists.
    positive_target = ctx.unique_name('sim2real-behav-restore-ok-')
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, positive_target))

    def _attempt_positive_restore():
        try:
            ddb.restore_table_to_point_in_time(
                SourceTableName=t,
                TargetTableName=positive_target,
                UseLatestRestorableTime=True,
            )
            return True
        except ClientError as exc:
            if exc.response['Error']['Code'] in (
                'InvalidRestoreTimeException',
                'PointInTimeRecoveryUnavailableException',
            ):
                return False
            raise

    _poll_until(
        _attempt_positive_restore,
        lambda ok: ok,
        timeout_s=90,
        interval_s=3.0,
        description='positive control: restore to latest restorable time accepted',
    )
    positive_status = _describe_status_or_none(ddb, positive_target)
    assert positive_status is not None, (
        f'positive control: {positive_target!r} was accepted by RestoreTableToPointInTime but an '
        f'independent describe_table cannot find it'
    )

    target = ctx.unique_name('sim2real-behav-restore-target-')
    ctx.on_cleanup(lambda: _delete_table_if_exists(ddb, target))
    future = datetime.now(timezone.utc) + timedelta(days=1)
    code, message = _error_code(
        lambda: ddb.restore_table_to_point_in_time(
            SourceTableName=t,
            TargetTableName=target,
            RestoreDateTime=future,
        )
    )
    assert code == ERR_INVALID_RESTORE_TIME, f'expected {ERR_INVALID_RESTORE_TIME}, got {code}'
    # The quoted instants (requested, earliest and latest restorable) are rendered and chosen by AWS.
    assert re.fullmatch(
        rf"RestoreDateTime '[^']+' must be within \w+ '[^']+' and \w+ '[^']+' for table '{re.escape(t)}'", message
    ), message

    not_found_status = _describe_status_or_none(ddb, target)
    assert not_found_status is None, (
        f'a rejected RestoreTableToPointInTime must not leave a target table behind, but '
        f'describe_table found {target!r} in status {not_found_status!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
