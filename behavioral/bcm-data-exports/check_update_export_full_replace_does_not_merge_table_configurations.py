"""update-export-full-replace-does-not-merge-table-configurations."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-export-full-replace-does-not-merge-table-configurations"
GROUP = "state"
SERVICES = ["bcm-data-exports"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExport fully replaces DataQuery.TableConfigurations (no merge with the prior value),
    and specifying it is mandatory on update for a COST_AND_USAGE_REPORT query -- omitting it
    is rejected, it is not silently kept from the previous definition."""
    bdx = ctx.client("bcm-data-exports")
    bucket = _create_export_bucket(ctx)
    name = ctx.unique_name("sim2real-bcmde-export-")
    table_configurations = {"COST_AND_USAGE_REPORT": {"TIME_GRANULARITY": "DAILY"}}
    arn = _create_export(ctx, bdx, _export_payload(
        ctx, name, bucket, "exports/", table_configurations=table_configurations,
    ))

    before = bdx.get_export(ExportArn=arn)["Export"]
    # AWS fills in default values (e.g. INCLUDE_RESOURCES=FALSE) for CUR 2.0 boolean table
    # configurations that weren't explicitly requested, so assert containment, not equality.
    before_table_config = before["DataQuery"].get("TableConfigurations", {}).get("COST_AND_USAGE_REPORT", {})
    expected_before = table_configurations["COST_AND_USAGE_REPORT"]["TIME_GRANULARITY"]
    assert before_table_config.get("TIME_GRANULARITY") == expected_before, (
        f"expected TIME_GRANULARITY={expected_before!r} on the created export, "
        f"got TableConfigurations={before_table_config!r}"
    )

    new_query = (
        "SELECT identity_line_item_id, line_item_product_code "
        "FROM COST_AND_USAGE_REPORT"
    )

    # Omitting TableConfigurations entirely on update is rejected -- it is mandatory for a
    # COST_AND_USAGE_REPORT query, not silently inherited/merged from the prior definition.
    no_table_config_payload = _export_payload(ctx, name, bucket, "exports/", query_statement=new_query)
    assert "TableConfigurations" not in no_table_config_payload["DataQuery"], (
        "test setup bug: payload should omit TableConfigurations entirely"
    )
    code, message = _error_code(lambda: bdx.update_export(ExportArn=arn, Export=no_table_config_payload))
    assert code == "ValidationException", (
        f"expected UpdateExport to reject a COST_AND_USAGE_REPORT query missing "
        f"TableConfigurations with ValidationException, got {code!r}"
    )
    expected_message = (
        "'TableConfigurations' must be provided when updating a COST_AND_USAGE_REPORT export"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    unchanged = bdx.get_export(ExportArn=arn)["Export"]
    assert unchanged["DataQuery"]["QueryStatement"] != new_query, (
        "rejected update must not apply: QueryStatement changed despite ValidationException"
    )

    # A full replace WITH a different TableConfigurations value fully overwrites -- the new
    # value wins outright, with no trace of the old DAILY value merged in.
    new_table_configurations = {"COST_AND_USAGE_REPORT": {"TIME_GRANULARITY": "MONTHLY"}}
    replacement = _export_payload(
        ctx, name, bucket, "exports/", query_statement=new_query,
        table_configurations=new_table_configurations,
    )
    bdx.update_export(ExportArn=arn, Export=replacement)

    after = bdx.get_export(ExportArn=arn)["Export"]
    assert after["DataQuery"]["QueryStatement"] == new_query, (
        f"expected QueryStatement to be fully replaced with {new_query!r}, "
        f"got {after['DataQuery']['QueryStatement']!r}"
    )
    after_table_config = after["DataQuery"]["TableConfigurations"]["COST_AND_USAGE_REPORT"]
    assert after_table_config["TIME_GRANULARITY"] == "MONTHLY", (
        f"expected the update to fully replace TIME_GRANULARITY with MONTHLY (no merge with "
        f"the prior DAILY value), got {after_table_config!r}"
    )


def _error_code(fn):
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
                    # bcm-data-exports export ARNs are always minted in us-east-1, regardless of
                    # ctx.region, so the SourceArn condition is pinned to match.
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
