"""create-get-export-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-get-export-round-trip"
GROUP = "control-plane"
SERVICES = ["bcm-data-exports"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateExport persists the full definition; GetExport echoes it and reports HEALTHY."""
    bdx = ctx.client("bcm-data-exports")
    bucket = _create_export_bucket(ctx, allow_delivery=True)
    name = ctx.unique_name("sim2real-bcmde-export-")
    query_statement = (
        "SELECT identity_line_item_id, line_item_product_code, line_item_unblended_cost "
        "FROM COST_AND_USAGE_REPORT"
    )
    table_configurations = {"COST_AND_USAGE_REPORT": {"TIME_GRANULARITY": "DAILY"}}
    payload = _export_payload(
        ctx, name, bucket, "exports/", query_statement=query_statement,
        table_configurations=table_configurations, description="sim2real round-trip check",
    )
    arn = _create_export(ctx, bdx, payload)

    got = bdx.get_export(ExportArn=arn)
    export = got["Export"]
    assert export["Name"] == name, f"expected persisted Name {name!r}, got {export['Name']!r}"
    assert export["Description"] == "sim2real round-trip check", (
        f"expected persisted Description 'sim2real round-trip check', got {export['Description']!r}"
    )
    assert export["DataQuery"]["QueryStatement"] == query_statement, (
        f"expected persisted QueryStatement {query_statement!r}, "
        f"got {export['DataQuery']['QueryStatement']!r}"
    )
    # AWS fills in default values (e.g. INCLUDE_RESOURCES=FALSE) for CUR 2.0 boolean table
    # configurations that weren't explicitly requested, so assert containment, not equality.
    got_table_config = export["DataQuery"]["TableConfigurations"]["COST_AND_USAGE_REPORT"]
    expected_granularity = table_configurations["COST_AND_USAGE_REPORT"]["TIME_GRANULARITY"]
    assert got_table_config["TIME_GRANULARITY"] == expected_granularity, (
        f"expected TIME_GRANULARITY {expected_granularity!r}, got {got_table_config['TIME_GRANULARITY']!r}"
    )
    dest = export["DestinationConfigurations"]["S3Destination"]
    assert dest["S3Bucket"] == bucket, f"expected S3Bucket {bucket!r}, got {dest['S3Bucket']!r}"
    assert dest["S3Prefix"] == "exports/", f"expected S3Prefix 'exports/', got {dest['S3Prefix']!r}"
    assert export["RefreshCadence"]["Frequency"] == "SYNCHRONOUS", (
        f"expected RefreshCadence.Frequency 'SYNCHRONOUS', got {export['RefreshCadence']['Frequency']!r}"
    )
    assert export["ExportArn"] == arn, f"expected GetExport to echo create ExportArn {arn!r}, got {export['ExportArn']!r}"
    assert got["ExportStatus"]["StatusCode"] == "HEALTHY", (
        f"expected ExportStatus.StatusCode 'HEALTHY' immediately after creation, "
        f"got {got['ExportStatus']['StatusCode']!r}"
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
                    # AWS Data Exports export ARNs always carry the us-east-1 region, whatever region
                    # the client calls, so the literal here tracks the service, not this check's region.
                    "ArnLike": {"aws:SourceArn": f"arn:aws:bcm-data-exports:us-east-1:{account}:export/*"},
                    "StringEquals": {"aws:SourceAccount": account},
                },
            }],
        }
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
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
