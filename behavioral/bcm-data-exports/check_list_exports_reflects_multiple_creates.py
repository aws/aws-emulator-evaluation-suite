"""list-exports-reflects-multiple-creates."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-exports-reflects-multiple-creates"
GROUP = "control-plane"
SERVICES = ["bcm-data-exports"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExports enumerates every export owned by the account, each HEALTHY and correctly named."""
    bdx = ctx.client("bcm-data-exports")
    bucket = _create_export_bucket(ctx)
    name_a = ctx.unique_name("sim2real-bcmde-a-")
    name_b = ctx.unique_name("sim2real-bcmde-b-")
    arn_a = _create_export(ctx, bdx, _export_payload(ctx, name_a, bucket, "exports/a/"))
    arn_b = _create_export(ctx, bdx, _export_payload(ctx, name_b, bucket, "exports/b/"))

    by_arn = {e["ExportArn"]: e for e in _list_all_exports(bdx)}
    assert arn_a in by_arn, f"expected {arn_a} in ListExports, got arns {sorted(by_arn)}"
    assert arn_b in by_arn, f"expected {arn_b} in ListExports, got arns {sorted(by_arn)}"
    assert by_arn[arn_a]["ExportName"] == name_a, (
        f"expected ExportName {name_a!r} for {arn_a}, got {by_arn[arn_a]['ExportName']!r}"
    )
    assert by_arn[arn_b]["ExportName"] == name_b, (
        f"expected ExportName {name_b!r} for {arn_b}, got {by_arn[arn_b]['ExportName']!r}"
    )
    assert by_arn[arn_a]["ExportStatus"]["StatusCode"] == "HEALTHY", (
        f"expected HEALTHY for {arn_a}, got {by_arn[arn_a]['ExportStatus']['StatusCode']!r}"
    )
    assert by_arn[arn_b]["ExportStatus"]["StatusCode"] == "HEALTHY", (
        f"expected HEALTHY for {arn_b}, got {by_arn[arn_b]['ExportStatus']['StatusCode']!r}"
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
                    # bcm-data-exports' control plane is pinned to us-east-1 regardless of ctx.region.
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
