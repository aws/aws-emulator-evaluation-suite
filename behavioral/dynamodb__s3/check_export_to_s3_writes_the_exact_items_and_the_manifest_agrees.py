"""export-to-s3-writes-the-exact-items-and-the-manifest-agrees."""
from __future__ import annotations

import gzip
import io
import json
import time

from behavioral_harness import tags

CHECK = "export-to-s3-writes-the-exact-items-and-the-manifest-agrees"
GROUP = 'export'
SERVICES = ['dynamodb', 's3']

_N_ITEMS = 12
#: A 12-item full export can take over 12 minutes on AWS; bounded well above that, and the
#: check fails rather than skips if it is not reached.
_EXPORT_BUDGET_S = 1800


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExportTableToPointInTime writes gzipped DynamoDB JSON to S3 whose decoded items equal the
    table, and the summary itemCount and per-data-file itemCounts agree with those items.
    """
    ddb = ctx.client('dynamodb')
    s3 = ctx.client('s3')

    bucket = ctx.unique_name('sim2real-xsvc-ddbexport-')
    kwargs = {'Bucket': bucket}
    if ctx.region != 'us-east-1':
        kwargs['CreateBucketConfiguration'] = {'LocationConstraint': ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={'TagSet': [{'Key': 'sim2real', 'Value': CHECK}]})

    def _empty_and_drop_bucket() -> None:
        token: dict = {}
        while True:
            page = s3.list_objects_v2(Bucket=bucket, **token)
            objects = [{'Key': o['Key']} for o in page.get('Contents', [])]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={'Objects': objects})
            if not page.get('IsTruncated'):
                break
            token = {'ContinuationToken': page['NextContinuationToken']}
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_drop_bucket)

    table = ctx.unique_name('sim2real-xsvc-ddbexport-')
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

    expected = set()
    for i in range(_N_ITEMS):
        item = {'pk': {'S': f'item-{i:02d}'}, 'n': {'N': str(i)}, 's': {'S': f'value-{i}'}}
        ddb.put_item(TableName=table, Item=item)
        expected.add(json.dumps(item, sort_keys=True))

    started = ddb.export_table_to_point_in_time(
        TableArn=table_arn, S3Bucket=bucket, S3Prefix='exp',
        ExportFormat='DYNAMODB_JSON')['ExportDescription']
    export_arn = started['ExportArn']

    deadline = time.time() + _EXPORT_BUDGET_S
    described = started
    while time.time() < deadline:
        described = ddb.describe_export(ExportArn=export_arn)['ExportDescription']
        if described['ExportStatus'] in ('COMPLETED', 'FAILED'):
            break
        time.sleep(2)
    assert described['ExportStatus'] == 'COMPLETED', (
        f'the export did not complete within {_EXPORT_BUDGET_S!r}s: status '
        f'{described["ExportStatus"]!r}, failure {described.get("FailureCode")!r} '
        f'{described.get("FailureMessage")!r}'
    )

    summary_key = described['ExportManifest']
    summary = json.loads(s3.get_object(Bucket=bucket, Key=summary_key)['Body'].read())
    assert summary['itemCount'] == _N_ITEMS, (
        f'the manifest itemCount disagrees with the table: {summary["itemCount"]!r}, expected '
        f'{_N_ITEMS!r}'
    )

    files_raw = s3.get_object(
        Bucket=bucket, Key=summary['manifestFilesS3Key'])['Body'].read().decode()
    entries = [json.loads(line) for line in files_raw.splitlines() if line.strip()]
    data_keys = [e['dataFileS3Key'] for e in entries]
    assert data_keys and all(k.endswith('.json.gz') for k in data_keys), (
        f'the export data objects are not gzipped DynamoDB JSON: {data_keys!r}'
    )
    assert sum(e['itemCount'] for e in entries) == _N_ITEMS, (
        f'the per-data-file itemCounts do not partition the table: '
        f'{[e["itemCount"] for e in entries]!r} over {_N_ITEMS!r} items'
    )

    decoded = set()
    for key in data_keys:
        blob = s3.get_object(Bucket=bucket, Key=key)['Body'].read()
        text = gzip.GzipFile(fileobj=io.BytesIO(blob)).read().decode()
        for line in text.splitlines():
            if line.strip():
                decoded.add(json.dumps(json.loads(line)['Item'], sort_keys=True))
    assert decoded == expected, (
        f'the exported items differ from the table contents: '
        f'{sorted(decoded ^ expected)!r}'
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
