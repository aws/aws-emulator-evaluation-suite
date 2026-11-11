"""concurrent-delete-export-exactly-one-succeeds."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-delete-export-exactly-one-succeeds"
GROUP = "concurrency"
SERVICES = ["bcm-data-exports"]

NOT_FOUND_MSG = "No matching definition found"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing DeleteExport against the same export: exactly one call succeeds, the rest 404."""
    bdx = ctx.client("bcm-data-exports")
    bucket = _create_export_bucket(ctx)
    name = ctx.unique_name("sim2real-bcmde-export-")
    arn = _create_export(ctx, bdx, _export_payload(ctx, name, bucket, "exports/"))

    def _attempt():
        from botocore.exceptions import ClientError
        try:
            bdx.delete_export(ExportArn=arn)
            return ("success", None)
        except ClientError as exc:
            return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    n_racers = 6
    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(lambda _: _attempt(), range(n_racers)))

    successes = [r for r in results if r[0] == "success"]
    others = [r for r in results if r[0] != "success"]
    assert len(successes) == 1, f"expected exactly 1 success, got {len(successes)} in {results}"
    assert len(others) == n_racers - 1, f"expected {n_racers - 1} non-success racers, got {len(others)} in {results}"
    assert all(code == "ResourceNotFoundException" for code, _ in others), (
        f"expected all non-winning racers to see ResourceNotFoundException, got {results}"
    )
    assert all(message == NOT_FOUND_MSG for _, message in others), (
        f"expected all non-winning racers to see message {NOT_FOUND_MSG!r}, got {results}"
    )

    code, message = _error_code(lambda: bdx.get_export(ExportArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code}"
    assert message == NOT_FOUND_MSG, f"expected message {NOT_FOUND_MSG!r} after delete, got {message!r}"


def _error_code(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_export_bucket(ctx, allow_delivery=True):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bcmde-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    if allow_delivery:
        account = _account_id(ctx)
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "EnableAWSDataExportsToWriteToS3",
                "Effect": "Allow",
                "Principal": {"Service": ["bcm-data-exports.amazonaws.com"]},
                "Action": ["s3:PutObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
                    # bcm-data-exports export ARNs always carry the us-east-1 region segment,
                    # regardless of which region the API was called in (shared across every
                    # check in this suite).
                    "ArnLike": {"aws:SourceArn": f"arn:aws:bcm-data-exports:us-east-1:{account}:export/*"},
                    "StringEquals": {"aws:SourceAccount": account},
                },
            }],
        }
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


def _export_payload(ctx, name, bucket, prefix, query_statement=None, table_configurations=None,
                     frequency="SYNCHRONOUS", description="sim2real behavioral check export"):
    data_query = {
        "QueryStatement": query_statement or (
            "SELECT identity_line_item_id, line_item_product_code, line_item_unblended_cost "
            "FROM COST_AND_USAGE_REPORT"
        )
    }
    if table_configurations is not None:
        data_query["TableConfigurations"] = table_configurations
    return {
        "Name": name,
        "Description": description,
        "DataQuery": data_query,
        "DestinationConfigurations": {
            "S3Destination": {
                "S3Bucket": bucket,
                "S3Prefix": prefix,
                "S3Region": ctx.region,
                "S3OutputConfigurations": {
                    "OutputType": "CUSTOM",
                    "Format": "TEXT_OR_CSV",
                    "Compression": "GZIP",
                    "Overwrite": "OVERWRITE_REPORT",
                },
            }
        },
        "RefreshCadence": {"Frequency": frequency},
    }


def _create_export(ctx, bdx, export_payload):
    resp = bdx.create_export(Export=export_payload)
    arn = resp["ExportArn"]

    def _cleanup():
        from botocore.exceptions import ClientError
        try:
            bdx.delete_export(ExportArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
