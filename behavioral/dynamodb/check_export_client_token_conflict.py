"""export-client-token-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-client-token-conflict"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']
ERR_EXPORT_CONFLICT = 'ExportConflictException'


def _error_code_and_message(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, so an
    emulator that accepts the conflicting retry never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f'expected {ERR_EXPORT_CONFLICT}, but the call SUCCEEDED and returned {result!r}')


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


def _delete_bucket(s3, bucket):
    try:
        while True:
            objs = s3.list_objects_v2(Bucket=bucket).get('Contents', [])
            if not objs:
                break
            failed = s3.delete_objects(Bucket=bucket, Delete={'Objects': [{'Key': o['Key']} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _make_bucket(ctx, s3):
    bucket = ctx.unique_name('sim2real-behav-export-').lower()
    if ctx.region == 'us-east-1':
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={'LocationConstraint': ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    return bucket


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing the SAME ClientToken from an already-submitted ExportTableToPointInTime for a second
    request with a changed parameter returns ExportConflictException rather than silently starting
    a second, independent export or replaying the first response unchanged.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    _enable_pitr(ctx, ddb, t)

    table_arn = ddb.describe_table(TableName=t)['Table']['TableArn']
    bucket = _make_bucket(ctx, ctx.client('s3'))
    token = ctx.unique_name('export-tok-')

    first = ddb.export_table_to_point_in_time(
        TableArn=table_arn,
        S3Bucket=bucket,
        ExportFormat='DYNAMODB_JSON',
        ClientToken=token,
    )
    assert first['ExportDescription']['ExportStatus'] in ('IN_PROGRESS', 'COMPLETED'), first

    code, message = _error_code_and_message(
        lambda: ddb.export_table_to_point_in_time(
            TableArn=table_arn,
            S3Bucket=bucket,
            ExportFormat='ION',  # changed parameter under the SAME ClientToken
            ClientToken=token,
        )
    )
    assert code == ERR_EXPORT_CONFLICT, f'expected {ERR_EXPORT_CONFLICT}, got {code}'
    expected_message = 'Export conflict: Duplicate request detected with conflicting parameters'
    assert message == expected_message, f'expected message {expected_message!r}, got {message!r}'

    # Independent read at the destination: the rejected, param-changed retry must not have
    # replayed the first response unchanged, nor started a second, independent export. The
    # original export is the only one that exists, and it still carries its original format.
    exports = ddb.list_exports(TableArn=table_arn)['ExportSummaries']
    assert len(exports) == 1, f'expected exactly 1 export for {table_arn}, got {exports}'
    first_arn = first['ExportDescription']['ExportArn']
    assert exports[0]['ExportArn'] == first_arn, f'expected {first_arn}, got {exports[0]}'
    desc = ddb.describe_export(ExportArn=first_arn)['ExportDescription']
    assert desc['ExportFormat'] == 'DYNAMODB_JSON', f'expected original format DYNAMODB_JSON, got {desc["ExportFormat"]}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
