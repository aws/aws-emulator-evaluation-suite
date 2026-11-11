"""export-invalid-time."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-invalid-time"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']
ERR_INVALID_EXPORT_TIME = 'InvalidExportTimeException'


def _expect_client_error(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises rather
    than reading as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'expected a ClientError, but the call succeeded and returned {result!r}')


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _enable_pitr(ddb, name):
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


def _start_export(ddb, table_arn, bucket, *, export_time=None, timeout_s=90, interval_s=3.0):
    """Start an export, retrying while PITR has not yet warmed up enough to serve one. A table
    that just reached PITR ENABLED does not necessarily have a servable restorable window yet."""
    kwargs = {'TableArn': table_arn, 'S3Bucket': bucket, 'ExportFormat': 'DYNAMODB_JSON'}
    if export_time is not None:
        kwargs['ExportTime'] = export_time

    def _attempt():
        try:
            return ddb.export_table_to_point_in_time(**kwargs)
        except ClientError as exc:
            if exc.response['Error']['Code'] != 'PointInTimeRecoveryUnavailableException':
                raise
            return None

    return _poll_until(
        _attempt, lambda r: r is not None, timeout_s=timeout_s, interval_s=interval_s,
        description='export accepted',
    )


def _delete_bucket(s3, bucket):
    # The positive-control export below writes to this bucket asynchronously, so objects can
    # still be arriving when cleanup starts: the empty-then-delete cycle is retried on
    # BucketNotEmpty every 2 s for up to 300 s. A bucket already gone is fine; anything else raises.
    deadline = time.monotonic() + 300.0
    while True:
        try:
            while True:
                objs = s3.list_objects_v2(Bucket=bucket).get('Contents', [])
                if not objs:
                    break
                failed = s3.delete_objects(Bucket=bucket, Delete={'Objects': [{'Key': o['Key']} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'NoSuchBucket':
                return
            if code != 'BucketNotEmpty' or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _make_bucket(ctx, s3):
    bucket = ctx.unique_name('sim2real-behav-export-').lower()
    if ctx.region == 'us-east-1':
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 itself.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={'LocationConstraint': ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={'TagSet': [{'Key': 'sim2real', 'Value': CHECK}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    return bucket


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ExportTableToPointInTime with an ExportTime outside the valid PITR window (a timestamp in
    the future) returns InvalidExportTimeException, while an export with a valid ExportTime on
    the same table and bucket succeeds and no new export is registered by the rejected call.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    _enable_pitr(ddb, t)

    table_arn = ddb.describe_table(TableName=t)['Table']['TableArn']
    bucket = _make_bucket(ctx, ctx.client('s3'))

    # Positive control: a valid ExportTime (default = now) must succeed on this same table and
    # bucket, so the future-time rejection below is proven to be about the timestamp and not
    # about a broken bucket, ARN or permission that would reject every export regardless of
    # ExportTime.
    positive = _start_export(ddb, table_arn, bucket)['ExportDescription']
    positive_arn = positive['ExportArn']
    assert positive['ExportStatus'] in ('IN_PROGRESS', 'COMPLETED'), (
        f'expected the valid-time export to start, got status {positive["ExportStatus"]!r}'
    )
    assert positive['TableArn'] == table_arn, f'expected TableArn {table_arn}, got {positive["TableArn"]}'

    exports_after_positive = {
        e['ExportArn'] for e in ddb.list_exports(TableArn=table_arn).get('ExportSummaries', [])
    }
    assert positive_arn in exports_after_positive, (
        f'expected {positive_arn} in ListExports, got {exports_after_positive}'
    )

    future = datetime.now(timezone.utc) + timedelta(days=1)
    code, message = _expect_client_error(
        lambda: ddb.export_table_to_point_in_time(
            TableArn=table_arn,
            S3Bucket=bucket,
            ExportFormat='DYNAMODB_JSON',
            ExportTime=future,
        )
    )
    assert code == ERR_INVALID_EXPORT_TIME, f'expected {ERR_INVALID_EXPORT_TIME}, got {code}'
    assert message == "Export Time is invalid", (
        f"expected the exact InvalidExportTimeException message AWS returns, got {message!r}"
    )

    exports_after_negative = {
        e['ExportArn'] for e in ddb.list_exports(TableArn=table_arn).get('ExportSummaries', [])
    }
    assert exports_after_negative == exports_after_positive, (
        f'expected no new export from the rejected call: had {exports_after_positive}, '
        f'now {exports_after_negative}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
