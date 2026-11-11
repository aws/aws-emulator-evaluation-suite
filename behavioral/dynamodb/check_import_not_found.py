"""import-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-not-found"
GROUP = 'errors'
SERVICES = ['dynamodb']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeImport on a just-started import returns its ARN, while an unknown import ARN raises
    ImportNotFoundException with the exact message.
    """
    ddb = ctx.client('dynamodb')
    s3 = ctx.client('s3')

    bucket = ctx.unique_name('sim2real-behav-import-').lower()
    if ctx.region == 'us-east-1':
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={'LocationConstraint': ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={'TagSet': [{'Key': 'sim2real', 'Value': CHECK}]})
    key = 'data/seed.json'
    body = json.dumps({'Item': {'pk': {'S': 'seed-1'}}}) + '\n'
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode('utf-8'))

    dest_table = ctx.unique_name('sim2real-behav-imported-')
    real_import = ddb.import_table(
        S3BucketSource={'S3Bucket': bucket, 'S3KeyPrefix': 'data/'},
        InputFormat='DYNAMODB_JSON',
        TableCreationParameters={
            'TableName': dest_table,
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}],
            'AttributeDefinitions': [{'AttributeName': 'pk', 'AttributeType': 'S'}],
            'BillingMode': 'PAY_PER_REQUEST',
        },
    )['ImportTableDescription']
    real_import_arn = real_import['ImportArn']
    ctx.on_cleanup(lambda: _wait_import_terminal_then_delete(ddb, real_import_arn, dest_table))

    # Positive control: DescribeImport finds the import we just started.
    found = ddb.describe_import(ImportArn=real_import_arn)['ImportTableDescription']
    assert found['ImportArn'] == real_import_arn, (
        f'positive control failed: expected DescribeImport to find {real_import_arn}, '
        f'got {found.get("ImportArn")}'
    )

    # Negative: a syntactically well-formed ImportArn under the same real
    # table that was never actually started.
    fake_import_arn = f'{found["TableArn"]}/import/01700000000000-aaaaaaaa'
    assert fake_import_arn != real_import_arn, 'fake import id collided with the real one'
    try:
        ddb.describe_import(ImportArn=fake_import_arn)
    except ClientError as exc:
        err = exc.response['Error']
    else:
        raise AssertionError(f'DescribeImport for the never-started {fake_import_arn} was ACCEPTED')
    assert err.get('Code') == 'ImportNotFoundException', (
        f"expected ImportNotFoundException, got {err.get('Code')}"
    )
    expected = f"Import not found: Import with arn: {fake_import_arn} doesn't exist"
    assert err.get('Message') == expected, (
        f'expected message {expected!r}, got {err.get("Message")!r}'
    )


def _empty_and_delete_bucket(s3, bucket):
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


def _wait_import_terminal_then_delete(ddb, import_arn, dest_table, timeout_s=420, interval_s=5):
    deadline = time.monotonic() + timeout_s
    terminal = {'COMPLETED', 'CANCELLED', 'FAILED'}
    while time.monotonic() < deadline:
        status = ddb.describe_import(ImportArn=import_arn)['ImportTableDescription']['ImportStatus']
        if status in terminal:
            break
        time.sleep(interval_s)
    try:
        ddb.delete_table(TableName=dest_table)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
