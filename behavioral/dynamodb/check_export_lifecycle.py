"""export-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-lifecycle"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


#: Budget for the export to reach a terminal state. A real DynamoDB export takes minutes.
_EXPORT_TERMINAL_TIMEOUT_S = 1200.0


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
    # S3 quirk, not a hardcoded target region: CreateBucket rejects an explicit
    # LocationConstraint for us-east-1 but requires one everywhere else. The bucket itself
    # always lands in ctx.region.
    if ctx.region == 'us-east-1':
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={'LocationConstraint': ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    return bucket


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExportTableToPointInTime produces an export job whose status progresses and is visible via
    DescribeExport / ListExports.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(TableName=t, KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST')
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    _enable_pitr(ddb, t)

    table_arn = ddb.describe_table(TableName=t)['Table']['TableArn']
    bucket = _make_bucket(ctx, ctx.client('s3'))

    export_resp = ddb.export_table_to_point_in_time(
        TableArn=table_arn, S3Bucket=bucket, ExportFormat='DYNAMODB_JSON'
    )
    export_arn = export_resp['ExportDescription']['ExportArn']
    export_status = export_resp['ExportDescription']['ExportStatus']
    assert export_status in ('IN_PROGRESS', 'COMPLETED'), (
        f'expected ExportTableToPointInTime status IN_PROGRESS or COMPLETED, got {export_status!r}'
    )
    assert export_resp['ExportDescription']['TableArn'] == table_arn, (
        f"expected ExportDescription.TableArn {table_arn!r}, "
        f"got {export_resp['ExportDescription']['TableArn']!r}"
    )

    desc = ddb.describe_export(ExportArn=export_arn)['ExportDescription']
    assert desc['ExportStatus'] in ('IN_PROGRESS', 'COMPLETED'), (
        f"expected DescribeExport status IN_PROGRESS or COMPLETED, got {desc['ExportStatus']!r}"
    )
    assert desc['S3Bucket'] == bucket, f"expected S3Bucket {bucket!r}, got {desc['S3Bucket']!r}"

    listed = ddb.list_exports(TableArn=table_arn)['ExportSummaries']
    assert any(e['ExportArn'] == export_arn for e in listed), (
        f'expected {export_arn} in ListExports, got {listed!r}'
    )

    # Observe the job actually reach a terminal state. `IN_PROGRESS or COMPLETED` is already
    # asserted twice above, so a poll on that predicate asserts nothing -- and worse, `_poll_until`
    # only returns when its predicate holds, so an assert on the returned value afterwards is dead
    # code that cannot fail. An export that never leaves IN_PROGRESS, or lands in FAILED, is a
    # fidelity gap rather than something to excuse.
    #
    # This needs minutes. The budget is a dedicated constant rather than whatever is left of a clock started before
    # `create_table` and two 120s PITR polls -- deriving it from that shared clock collapsed it to
    # the floor and made the assertion unreliable for a reason unrelated to the target.
    terminal = _poll_until(
        lambda: ddb.describe_export(ExportArn=export_arn)['ExportDescription'],
        lambda d: d['ExportStatus'] in ('COMPLETED', 'FAILED'),
        timeout_s=_EXPORT_TERMINAL_TIMEOUT_S,
        interval_s=10.0,
        description='export reached a terminal state',
    )
    assert terminal['ExportStatus'] == 'COMPLETED', (
        f"expected the export to reach COMPLETED, got {terminal['ExportStatus']!r}: {terminal!r}"
    )
    assert terminal['ExportFormat'] == 'DYNAMODB_JSON', (
        f"expected ExportFormat DYNAMODB_JSON, got {terminal['ExportFormat']!r}"
    )
    # Confirmed on real AWS: DescribeExport omits ExportType entirely for a request that never
    # specified an IncrementalExportSpecification -- it is not defaulted to 'FULL_EXPORT' in the
    # response, so asserting its presence would fail against a correct target.

    listed_after = ddb.list_exports(TableArn=table_arn)['ExportSummaries']
    assert any(e['ExportArn'] == export_arn and e.get('ExportStatus') == 'COMPLETED' for e in listed_after), (
        f'expected {export_arn} COMPLETED in post-terminal ListExports, got {listed_after!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
