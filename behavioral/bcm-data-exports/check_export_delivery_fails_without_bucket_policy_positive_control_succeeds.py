"""export-delivery-fails-without-bucket-policy-positive-control-succeeds."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "export-delivery-fails-without-bucket-policy-positive-control-succeeds"
GROUP = "overly-permissive"
SERVICES = ["bcm-data-exports"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateExport to a bucket without the delivery-grant policy fails at once with ValidationException
    "S3 bucket permission validation failed" and creates no export, while a policied bucket's export is
    HEALTHY, and granting the same policy makes the identical call succeed."""
    bdx = ctx.client("bcm-data-exports")
    good_bucket = _create_export_bucket(ctx, allow_delivery=True)
    bad_bucket = _create_export_bucket(ctx, allow_delivery=False)

    # Positive control: a correctly-policied bucket accepts CreateExport.
    good_name = ctx.unique_name("sim2real-bcmde-good-")
    good_arn = _create_export(ctx, bdx, _export_payload(ctx, good_name, good_bucket, "exports/"))
    good_export = bdx.get_export(ExportArn=good_arn)["Export"]
    assert good_export["Name"] == good_name, (
        f"expected the correctly-policied CreateExport call to be accepted, got {good_export!r}"
    )
    good_export_status = bdx.get_export(ExportArn=good_arn)["ExportStatus"]
    assert good_export_status["StatusCode"] == "HEALTHY", (
        f"expected the correctly-policied export to report HEALTHY, got {good_export_status!r}"
    )

    # Break exactly one thing: point an identical export at a bucket with no delivery-grant policy.
    bad_name = ctx.unique_name("sim2real-bcmde-bad-")
    code, message = _create_export_rejected(ctx, bdx, _export_payload(ctx, bad_name, bad_bucket, "exports/"))
    assert code == "ValidationException", f"expected CreateExport to reject with ValidationException, got {code!r}"
    assert message == "S3 bucket permission validation failed", (
        f"expected the rejection to name the S3 bucket permission gap specifically, got {message!r}"
    )

    names = {e["ExportName"] for e in _list_all_exports(bdx)}
    assert bad_name not in names, f"the rejected export {bad_name!r} must not have been created"

    # Restore: grant the identical policy on the same bucket, and the identical call now succeeds.
    _grant_delivery_policy(ctx, bad_bucket, _account_id(ctx))
    bad_arn = _create_export(ctx, bdx, _export_payload(ctx, bad_name, bad_bucket, "exports/"))
    created = bdx.get_export(ExportArn=bad_arn)["Export"]
    assert created["Name"] == bad_name, (
        f"expected the identical call to succeed once the bucket policy was granted, got {created!r}"
    )


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


def _grant_delivery_policy(ctx, bucket, account):
    s3 = ctx.client("s3")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "EnableAWSDataExportsToWriteToS3",
            "Effect": "Allow",
            "Principal": {"Service": ["bcm-data-exports.amazonaws.com"]},
            "Action": ["s3:PutObject"],
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {
                # AWS Data Exports runs in us-east-1 regardless of ctx.region, so the export's
                # SourceArn is always us-east-1 here.
                "ArnLike": {"aws:SourceArn": f"arn:aws:bcm-data-exports:us-east-1:{account}:export/*"},
                "StringEquals": {"aws:SourceAccount": account},
            },
        }],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _create_export_bucket(ctx, allow_delivery=True):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bcmde-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})
    if allow_delivery:
        _grant_delivery_policy(ctx, bucket, _account_id(ctx))
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


def _create_export_rejected(ctx, bdx, export_payload):
    """CreateExport must raise. An unexpected success raises too, so accepting the call fails as
    itself and not as a bare code mismatch."""
    from botocore.exceptions import ClientError

    try:
        resp = bdx.create_export(Export=export_payload)
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")

    arn = resp["ExportArn"]
    bdx.tag_resource(ResourceArn=arn, ResourceTags=[{"Key": "simparity-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: bdx.delete_export(ExportArn=arn))
    raise AssertionError(
        f"expected CreateExport to be rejected for {export_payload['Name']!r} against an "
        f"unpolicied bucket, but it succeeded: {resp!r}"
    )


def _list_all_exports(bdx):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = bdx.list_exports(**kwargs)
        out.extend(resp.get("Exports", []))
        token = resp.get("NextToken")
        if not token:
            return out


def _create_export(ctx, bdx, export_payload):
    resp = bdx.create_export(Export=export_payload)
    arn = resp["ExportArn"]
    bdx.tag_resource(ResourceArn=arn, ResourceTags=[{"Key": "simparity-check", "Value": CHECK}])

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
