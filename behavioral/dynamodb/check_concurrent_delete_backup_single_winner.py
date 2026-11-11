"""concurrent-delete-backup-single-winner."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "concurrent-delete-backup-single-winner"
GROUP = 'concurrency'
SERVICES = ['dynamodb']
ERR_BACKUP_NOT_FOUND = 'BackupNotFoundException'
#: table_exists waiter bound: 2 s x 90 attempts.
_WAITER = {'Delay': 2, 'MaxAttempts': 90}


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'expected this call to be rejected, but it SUCCEEDED and returned {result!r}')


def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N concurrent DeleteBackup calls on the SAME AVAILABLE backup yield exactly one success;
    every other racer gets BackupNotFoundException, and a final DescribeBackup confirms it is gone.
    Tagged axis:rejection: the graded half is the losers' error, not the one success.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST', Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig=_WAITER)

    # Immediately after CreateTable, the continuous-backups infra may still be provisioning
    # (CreateBackup then raises ContinuousBackupsUnavailableException) -- wait it out.
    _poll_until(
        lambda: ddb.describe_continuous_backups(TableName=t)['ContinuousBackupsDescription'],
        lambda d: d['ContinuousBackupsStatus'] == 'ENABLED',
        timeout_s=max(1.0, min(90.0, (ctx.time_left() or 90.0) - 5.0)),
        interval_s=2.0,
        description='continuous backups ready',
    )

    backup_arn = ddb.create_backup(TableName=t, BackupName=ctx.unique_name('bkp-'))[
        'BackupDetails'
    ]['BackupArn']
    _poll_until(
        lambda: ddb.describe_backup(BackupArn=backup_arn)['BackupDescription']['BackupDetails'][
            'BackupStatus'
        ],
        lambda s: s == 'AVAILABLE',
        timeout_s=max(1.0, min(120.0, (ctx.time_left() or 120.0) - 5.0)),
        interval_s=2.0,
        description='backup AVAILABLE',
    )

    n = 6
    results = _run_concurrent(
        [lambda: ddb.delete_backup(BackupArn=backup_arn) for _ in range(n)], timeout_s=90
    )
    successes = _concurrent_successes(results)
    assert successes == 1, f'expected exactly one winning DeleteBackup, got {successes}: {results}'

    codes = _concurrent_error_codes(results)
    assert len(codes) == n - 1, f'expected {n - 1} losing racers, got {len(codes)}: {codes}'
    assert all(c == ERR_BACKUP_NOT_FOUND for c in codes), (
        f'expected every losing racer to get {ERR_BACKUP_NOT_FOUND}, got {codes}'
    )

    final_code, final_message = _error_code(lambda: ddb.describe_backup(BackupArn=backup_arn))
    assert final_code == ERR_BACKUP_NOT_FOUND, f'expected {ERR_BACKUP_NOT_FOUND}, got {final_code}'
    assert final_message == f"Backup not found: {backup_arn}", (
        f"expected AWS's exact BackupNotFoundException message, got {final_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
