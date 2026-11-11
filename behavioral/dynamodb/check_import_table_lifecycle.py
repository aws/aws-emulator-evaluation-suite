"""import-table-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-table-lifecycle"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _empty_and_delete_bucket(s3, bucket):
    try:
        paginator = s3.get_paginator('list_object_versions')
        for page in paginator.paginate(Bucket=bucket):
            objs = [
                {'Key': v['Key'], 'VersionId': v['VersionId']}
                for v in page.get('Versions', []) + page.get('DeleteMarkers', [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={'Objects': objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _safe_delete_table(ddb, table_name):
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ImportTable runs to COMPLETED with ImportedItemCount 1, the imported row reads back from the new table with
    GetItem, and ListImports lists the job while it runs and after it completes.
    """
    ddb = ctx.client('dynamodb')
    s3 = ctx.client('s3')

    bucket = ctx.unique_name('sim2real-behav-import-').lower()
    if ctx.region == 'us-east-1':
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={'LocationConstraint': ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    key = 'data/seed.json'
    body = json.dumps({'Item': {'pk': {'S': 'seed-1'}, 'v': {'S': 'hello'}}}) + '\n'
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode('utf-8'))

    target_name = ctx.unique_name('sim2real-behav-imported-')
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, target_name))
    import_resp = ddb.import_table(
        S3BucketSource={'S3Bucket': bucket, 'S3KeyPrefix': 'data/'},
        InputFormat='DYNAMODB_JSON',
        TableCreationParameters={
            'TableName': target_name,
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            'AttributeDefinitions': [{'AttributeName': 'pk', 'AttributeType': 'S'}],
            'BillingMode': 'PAY_PER_REQUEST',
        },
    )
    import_arn = import_resp['ImportTableDescription']['ImportArn']
    initial_status = import_resp['ImportTableDescription']['ImportStatus']
    assert initial_status in ('IN_PROGRESS', 'COMPLETED'), (
        f'expected IN_PROGRESS or COMPLETED right after ImportTable, got {initial_status!r}'
    )

    desc = ddb.describe_import(ImportArn=import_arn)['ImportTableDescription']
    assert desc['ImportStatus'] in ('IN_PROGRESS', 'COMPLETED'), (
        f"expected a status reachable moments after creation, got {desc['ImportStatus']!r}"
    )
    table_arn = desc['TableArn']

    listed = ddb.list_imports(TableArn=table_arn)['ImportSummaryList']
    assert any(i['ImportArn'] == import_arn for i in listed), (
        f'{import_arn} not found in ListImports right after creation: {listed!r}'
    )

    final = _poll_until(
        lambda: ddb.describe_import(ImportArn=import_arn)['ImportTableDescription'],
        lambda d: d['ImportStatus'] in ('COMPLETED', 'FAILED', 'CANCELLED'),
        timeout_s=600,
        interval_s=15.0,
        description='import reaching a terminal state',
    )
    assert final['ImportStatus'] == 'COMPLETED', (
        'expected the import of a single well-formed DYNAMODB_JSON row to COMPLETE, got '
        f"{final['ImportStatus']!r}: {final!r}"
    )
    assert final['ImportedItemCount'] == 1, (
        f"expected exactly the 1 seed row to be imported, got {final['ImportedItemCount']!r}"
    )

    item = ddb.get_item(TableName=target_name, Key={'pk': {'S': 'seed-1'}}).get('Item')
    assert item is not None, 'seed-1 not found in the imported table via an independent get_item'
    assert item['v']['S'] == 'hello', f'expected v=hello for the imported row, got {item!r}'

    listed_after = ddb.list_imports(TableArn=table_arn)['ImportSummaryList']
    assert any(i['ImportArn'] == import_arn for i in listed_after), (
        f'{import_arn} dropped out of ListImports once COMPLETED: {listed_after!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
