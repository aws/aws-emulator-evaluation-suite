"""import-target-in-use."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-target-in-use"
GROUP = 'table_lifecycle'
SERVICES = ['dynamodb']


def _poll_until(probe, predicate, *, timeout_s=180, interval_s=3.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return None


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


def _delete_table_retrying(ddb, table_name, *, timeout_s=60, interval_s=3.0):
    """Retry DeleteTable through the transient ResourceInUseException a just-issued TagResource
    leaves while it propagates."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            if exc.response['Error']['Code'] != 'ResourceInUseException':
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f'delete_table did not succeed within {timeout_s}s: {last_exc}')


def _make_bucket(ctx, s3):
    bucket = ctx.unique_name('sim2real-behav-import-').lower()
    # us-east-1 is the one region S3 CreateBucket rejects a LocationConstraint for.
    if ctx.region == 'us-east-1':
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={'LocationConstraint': ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={'TagSet': [{'Key': 'sim2real', 'Value': CHECK}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    return bucket


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two ImportTable calls racing for the same new TableName are both accepted, but exactly one
    settles to FAILED with FailureCode TableAlreadyExists, so only one live table is created."""
    ddb = ctx.client('dynamodb')
    s3 = ctx.client('s3')
    bucket = _make_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key='data/import.csv', Body=b'pk\nrow1\n')

    target_name = ctx.unique_name('sim2real-behav-import-tgt-')
    ctx.on_cleanup(lambda: _delete_table_retrying(ddb, target_name))
    table_creation_params = dict(
        TableName=target_name,
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        BillingMode='PAY_PER_REQUEST',
    )
    import_kwargs = dict(
        S3BucketSource={'S3Bucket': bucket, 'S3KeyPrefix': 'data/'},
        InputFormat='CSV',
        InputFormatOptions={'Csv': {'Delimiter': ',', 'HeaderList': ['pk']}},
    )

    first = ddb.import_table(TableCreationParameters=table_creation_params, **import_kwargs)
    first_arn = first['ImportTableDescription']['ImportArn']
    assert first['ImportTableDescription']['ImportStatus'] in ('IN_PROGRESS', 'COMPLETED'), first

    # Before the first import creates its table, a conflicting second call is accepted.
    second = ddb.import_table(TableCreationParameters=table_creation_params, **import_kwargs)
    second_arn = second['ImportTableDescription']['ImportArn']
    assert second['ImportTableDescription']['ImportStatus'] in ('IN_PROGRESS', 'COMPLETED'), second

    def _settle(arn):
        return _poll_until(
            lambda: ddb.describe_import(ImportArn=arn)['ImportTableDescription'],
            lambda d: d['ImportStatus'] in ('COMPLETED', 'FAILED', 'CANCELLED'),
            timeout_s=180,
            interval_s=3.0,
            description=f'import {arn} settles',
        )

    first_final = _settle(first_arn)
    second_final = _settle(second_arn)
    if first_final is None or second_final is None:
        raise AssertionError(
            "one or both ImportTable jobs did not reach a terminal state within the observation "
            "budget (ImportTable has no documented completion-time bound)"
        )

    statuses = {first_final['ImportStatus'], second_final['ImportStatus']}
    assert 'FAILED' in statuses, (
        f"expected at least one of the two conflicting imports (same TableName) to FAIL, got "
        f"{first_final['ImportStatus']!r} and {second_final['ImportStatus']!r}"
    )
    assert not (first_final['ImportStatus'] == second_final['ImportStatus'] == 'FAILED'), (
        "expected exactly one of the two conflicting imports to survive (create the live table), "
        f"but BOTH settled to FAILED: {first_final} / {second_final}"
    )
    failed = first_final if first_final['ImportStatus'] == 'FAILED' else second_final
    # The loser's FailureCode is TableAlreadyExists only once the table exists, so the winner's
    # table is tagged here for tag-based cleanup.
    table_arn = ddb.describe_table(TableName=target_name)['Table']['TableArn']
    ddb.tag_resource(ResourceArn=table_arn, Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    # Which of the two jobs loses varies per run; the loser's FailureCode is the bare
    # 'TableAlreadyExists' string, not a ClientError-style '...Exception' name.
    failure_code = failed.get('FailureCode')
    assert failure_code == 'TableAlreadyExists', (
        f'expected FailureCode TableAlreadyExists, got {failure_code!r}: {failed}'
    )
    # message varies: the loser's FailureMessage depends on how far the winner got when the loser
    # reached the table -- 'Table already exists' or 'Attempt to change a resource which is still
    # in use: Table: <name> is being used.' -- so only the FailureCode is graded.


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
