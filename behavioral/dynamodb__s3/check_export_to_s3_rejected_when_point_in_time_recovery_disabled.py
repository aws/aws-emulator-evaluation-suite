"""export-to-s3-rejected-when-point-in-time-recovery-disabled."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-to-s3-rejected-when-point-in-time-recovery-disabled"
GROUP = 'export'
SERVICES = ['dynamodb', 's3']

_N_ITEMS = 3
ERR_NO_PITR = 'PointInTimeRecoveryUnavailableException'
#: A small full export can take over 12 minutes on AWS; bounded well above that.
_EXPORT_BUDGET_S = 1800


@tags("axis:rejection", "cap:c2", "concern:e2e", "concern:negative-classes",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """ExportTableToPointInTime on a table with PITR off fails with PITR-unavailable, leaves no
    export record and no objects in the bucket; enabling PITR alone makes the same call complete.
    """
    ddb = ctx.client('dynamodb')
    s3 = ctx.client('s3')

    bucket = ctx.unique_name('sim2real-xsvc-ddbnopitr-')
    kwargs = {'Bucket': bucket}
    if ctx.region != 'us-east-1':
        kwargs['CreateBucketConfiguration'] = {'LocationConstraint': ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={'TagSet': [{'Key': 'sim2real', 'Value': CHECK}]})

    def _list_bucket() -> list[str]:
        keys: list[str] = []
        token: dict = {}
        while True:
            page = s3.list_objects_v2(Bucket=bucket, **token)
            keys += [o['Key'] for o in page.get('Contents', [])]
            if not page.get('IsTruncated'):
                return keys
            token = {'ContinuationToken': page['NextContinuationToken']}

    def _empty_and_drop_bucket() -> None:
        while True:
            keys = _list_bucket()
            if not keys:
                break
            s3.delete_objects(Bucket=bucket,
                              Delete={'Objects': [{'Key': k} for k in keys[:1000]]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_drop_bucket)

    table = ctx.unique_name('sim2real-xsvc-ddbnopitr-')
    ddb.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    table_arn = ddb.describe_table(TableName=table)['Table']['TableArn']

    for i in range(_N_ITEMS):
        ddb.put_item(TableName=table, Item={'pk': {'S': f'item-{i:02d}'},
                                            's': {'S': f'value-{i}'}})

    # PITR is off -- the one broken thing. Capture the response of the call expected to fail:
    # if the service wrongly ACCEPTS it, an export exists and the assertion below must say so
    # rather than aborting before the export is named.
    accepted = None
    rejected = None
    try:
        accepted = ddb.export_table_to_point_in_time(
            TableArn=table_arn, S3Bucket=bucket, S3Prefix='exp',
            ExportFormat='DYNAMODB_JSON')['ExportDescription']
    except ClientError as exc:
        rejected = exc.response

    assert rejected is not None, (
        f'exporting a table with point-in-time recovery disabled must be rejected, but the '
        f'service accepted it: {json.dumps(accepted, default=str)}'
    )
    code = rejected['Error']['Code']
    message = rejected['Error']['Message']
    assert code == ERR_NO_PITR, (
        f'expected {ERR_NO_PITR!r} when PITR is disabled, got {code!r} '
        f'({rejected["Error"].get("Message")!r})'
    )
    assert message == f"Point in time recovery is not enabled for table '{table}'", (
        f"expected the exact PointInTimeRecoveryUnavailableException message AWS returns, got {message!r}"
    )

    # Effect absent, twice over: no export record, and not one byte in the destination.
    summaries = []
    token: dict = {}
    while True:
        page = ddb.list_exports(TableArn=table_arn, **token)
        summaries += page.get('ExportSummaries') or []
        if not page.get('NextToken'):
            break
        token = {'NextToken': page['NextToken']}
    assert summaries == [], (
        f'the rejected export still created an export record: {summaries!r}'
    )
    after_rejection = _list_bucket()
    assert after_rejection == [], (
        f'the rejected export still wrote objects into the destination bucket: '
        f'{after_rejection!r}'
    )

    # Positive control: repair only PITR and the identical call completes and fills that bucket.
    _enable_pitr(ctx, ddb, table)
    deadline = time.time() + 300
    pitr = None
    while time.time() < deadline:
        pitr = ddb.describe_continuous_backups(TableName=table)[
            'ContinuousBackupsDescription']['PointInTimeRecoveryDescription'][
            'PointInTimeRecoveryStatus']
        if pitr == 'ENABLED':
            break
        time.sleep(2)
    assert pitr == 'ENABLED', f'point-in-time recovery never became ENABLED: {pitr!r}'

    export_arn = ddb.export_table_to_point_in_time(
        TableArn=table_arn, S3Bucket=bucket, S3Prefix='exp',
        ExportFormat='DYNAMODB_JSON')['ExportDescription']['ExportArn']
    deadline = time.time() + _EXPORT_BUDGET_S
    described: dict = {}
    while time.time() < deadline:
        described = ddb.describe_export(ExportArn=export_arn)['ExportDescription']
        if described['ExportStatus'] in ('COMPLETED', 'FAILED'):
            break
        time.sleep(2)
    assert described.get('ExportStatus') == 'COMPLETED', (
        f'the control export did not complete within {_EXPORT_BUDGET_S!r}s, so the rejection '
        f'above cannot be attributed to PITR alone: {described.get("ExportStatus")!r} '
        f'{described.get("FailureCode")!r} {described.get("FailureMessage")!r}'
    )
    summary = json.loads(
        s3.get_object(Bucket=bucket, Key=described['ExportManifest'])['Body'].read())
    assert summary['itemCount'] == _N_ITEMS, (
        f'the control export wrote the wrong number of items: {summary["itemCount"]!r}, expected '
        f'{_N_ITEMS!r}'
    )


def _enable_pitr(ctx, ddb, table: str) -> None:
    """UpdateContinuousBackups, retried while AWS still initialises a new table's backups."""
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else min(120.0, left))
    while True:
        try:
            ddb.update_continuous_backups(
                TableName=table,
                PointInTimeRecoverySpecification={'PointInTimeRecoveryEnabled': True})
            return
        except ddb.exceptions.ContinuousBackupsUnavailableException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
