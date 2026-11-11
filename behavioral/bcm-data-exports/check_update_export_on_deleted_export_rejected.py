"""update-export-on-deleted-export-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-export-on-deleted-export-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-data-exports"]

NOT_FOUND_MSG = "No matching definition found"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExport against an ExportArn that has just been deleted is rejected, not recreated."""
    bdx = ctx.client("bcm-data-exports")
    bucket = _create_export_bucket(ctx)
    name = ctx.unique_name("sim2real-bcmde-export-")
    arn = _create_export(ctx, bdx, _export_payload(ctx, name, bucket, "exports/"))
    bdx.delete_export(ExportArn=arn)

    new_query = "SELECT identity_line_item_id FROM COST_AND_USAGE_REPORT"
    table_configurations = {"COST_AND_USAGE_REPORT": {"TIME_GRANULARITY": "DAILY"}}
    replacement = _export_payload(
        ctx, name, bucket, "exports/", query_statement=new_query, table_configurations=table_configurations,
    )
    code, message = _error_code(lambda: bdx.update_export(ExportArn=arn, Export=replacement))
    assert code == "ResourceNotFoundException", (
        f"UpdateExport on a just-deleted ExportArn should fail ResourceNotFoundException, got {code!r}"
    )
    assert message == NOT_FOUND_MSG, f"expected message {NOT_FOUND_MSG!r}, got {message!r}"

    # The update must not have resurrected/created the export under that ARN.
    still_gone_code, still_gone_message = _error_code(lambda: bdx.get_export(ExportArn=arn))
    assert still_gone_code == "ResourceNotFoundException", (
        f"GetExport for {arn} should still be ResourceNotFoundException after the rejected update, "
        f"got {still_gone_code!r}"
    )
    assert still_gone_message == NOT_FOUND_MSG, (
        f"expected message {NOT_FOUND_MSG!r} after the rejected update, got {still_gone_message!r}"
    )

    # Positive control: updating a real, still-existing export succeeds.
    other_name = ctx.unique_name("sim2real-bcmde-export-")
    other_arn = _create_export(ctx, bdx, _export_payload(ctx, other_name, bucket, "exports/"))
    bdx.update_export(
        ExportArn=other_arn,
        Export=_export_payload(
            ctx, other_name, bucket, "exports/", query_statement=new_query,
            table_configurations=table_configurations,
        ),
    )
    updated_query = bdx.get_export(ExportArn=other_arn)["Export"]["DataQuery"]["QueryStatement"]
    assert updated_query == new_query, (
        f"positive control: UpdateExport on a live export should take effect, "
        f"expected QueryStatement {new_query!r}, got {updated_query!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
                    # bcm-data-exports is a billing control plane whose resource ARNs are pinned to
                    # us-east-1 regardless of which region the caller dials (like iam/sts globals).
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
