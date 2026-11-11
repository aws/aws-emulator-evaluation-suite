"""get-export-cross-account-arn-isolated."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-export-cross-account-arn-isolated"
GROUP = "overly-permissive"
SERVICES = ["bcm-data-exports"]

NOT_FOUND_MSG = "No matching definition found"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ARN naming a different (fake) account 404s -- no cross-tenant leak, no AccessDenied tell."""
    bdx = ctx.client("bcm-data-exports")
    other_account = "111122223333"
    # AWS Data Exports export ARNs always carry the us-east-1 region, whatever region the
    # client calls.
    fake_arn = (
        f"arn:aws:bcm-data-exports:us-east-1:{other_account}:"
        "export/isolated-test/00000000-0000-0000-0000-000000000000"
    )

    get_code, get_message = _error_code(lambda: bdx.get_export(ExportArn=fake_arn))
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a cross-account GetExport, got {get_code!r}"
    )
    assert get_message == NOT_FOUND_MSG, (
        f"expected message {NOT_FOUND_MSG!r} for a cross-account GetExport, got {get_message!r}"
    )

    # ListTagsForResource validates that the ResourceArn's account matches the caller's account
    # before any existence check, so a cross-account ARN is rejected as ValidationException.
    tag_code, tag_message = _error_code(lambda: bdx.list_tags_for_resource(ResourceArn=fake_arn))
    assert tag_code == "ValidationException", (
        f"expected ValidationException for a cross-account ListTagsForResource, got {tag_code!r}"
    )
    assert tag_message == "Resource doesn't support tagging", (
        f"expected message \"Resource doesn't support tagging\" for a cross-account "
        f"ListTagsForResource, got {tag_message!r}"
    )

    # Positive control: the caller's own real export is fetched, and its own tags are listable --
    # without this, a ListTagsForResource that always raises ValidationException would pass too.
    bucket = _create_export_bucket(ctx)
    name = ctx.unique_name("sim2real-bcmde-export-")
    arn = _create_export(ctx, bdx, _export_payload(ctx, name, bucket, "exports/"))
    got = bdx.get_export(ExportArn=arn)["Export"]["Name"]
    assert got == name, f"expected the created export's Name to be {name!r}, got {got!r}"

    own_tags = bdx.list_tags_for_resource(ResourceArn=arn)
    assert "ResourceTags" in own_tags, (
        f"expected ListTagsForResource on the caller's own export to succeed, got {own_tags!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
