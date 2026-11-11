"""get-export-nonexistent-arn-not-found."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-export-nonexistent-arn-not-found"
GROUP = "error-semantics"
SERVICES = ["bcm-data-exports"]

NOT_FOUND_MSG = "No matching definition found"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExport for a well-formed but nonexistent ExportArn returns ResourceNotFoundException."""
    bdx = ctx.client("bcm-data-exports")
    account = _account_id(ctx)
    # us-east-1 literal: BCM Data Exports is a billing service pinned to us-east-1 --
    # every export ARN carries that region regardless of ctx.region.
    bogus_arn = (
        f"arn:aws:bcm-data-exports:us-east-1:{account}:"
        "export/does-not-exist/00000000-0000-0000-0000-000000000000"
    )
    code, message = _error_code(lambda: bdx.get_export(ExportArn=bogus_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == NOT_FOUND_MSG, f"expected message {NOT_FOUND_MSG!r}, got {message!r}"

    # Positive control: a real export is fetched successfully.
    bucket = _create_export_bucket(ctx)
    name = ctx.unique_name("sim2real-bcmde-export-")
    arn = _create_export(ctx, bdx, _export_payload(ctx, name, bucket, "exports/"))
    got = bdx.get_export(ExportArn=arn)
    assert got["Export"]["Name"] == name, f"expected export name {name!r}, got {got['Export'].get('Name')!r}"


def _error_code(fn):
    # An unexpected SUCCESS raises rather than returning a falsy sentinel.
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    if allow_delivery:
        account = _account_id(ctx)
        # us-east-1 literal: BCM Data Exports is pinned to us-east-1, so every export's SourceArn
        # carries that region regardless of ctx.region.
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "EnableAWSDataExportsToWriteToS3",
                "Effect": "Allow",
                "Principal": {"Service": ["bcm-data-exports.amazonaws.com"]},
                "Action": ["s3:PutObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
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
    resp = bdx.create_export(
        Export=export_payload,
        ResourceTags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
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
