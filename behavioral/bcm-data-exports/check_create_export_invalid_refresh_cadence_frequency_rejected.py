"""create-export-invalid-refresh-cadence-frequency-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-export-invalid-refresh-cadence-frequency-rejected"
GROUP = "error-semantics"
SERVICES = ["bcm-data-exports"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateExport rejects a RefreshCadence.Frequency other than the supported SYNCHRONOUS value."""
    bdx = ctx.client("bcm-data-exports")
    bucket = _create_export_bucket(ctx)
    bad_name = ctx.unique_name("sim2real-bcmde-badfreq-")
    bad_payload = _export_payload(ctx, bad_name, bucket, "exports/", frequency="DAILY")

    code, message = _error_code(lambda: bdx.create_export(Export=bad_payload))
    assert code == "ValidationException", f"expected ValidationException for frequency=DAILY, got {code!r}"
    expected_message = (
        "1 validation error detected: Value 'DAILY' at 'export.refreshCadence.frequency' failed to "
        "satisfy constraint: Member must satisfy enum value set: [SYNCHRONOUS]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    names = {e["ExportName"] for e in _list_all_exports(bdx)}
    assert bad_name not in names, f"rejected export {bad_name!r} must not appear in ListExports, saw {names!r}"

    # Positive control: the documented SYNCHRONOUS frequency succeeds.
    good_name = ctx.unique_name("sim2real-bcmde-export-")
    arn = _create_export(ctx, bdx, _export_payload(ctx, good_name, bucket, "exports/"))
    got = bdx.get_export(ExportArn=arn)["Export"]
    got_freq = got["RefreshCadence"]["Frequency"]
    assert got_freq == "SYNCHRONOUS", f"expected RefreshCadence.Frequency=SYNCHRONOUS, got {got_freq!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
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
                    # bcm-data-exports is a region-pinned control plane, so the export ARN is
                    # always us-east-1
                    # regardless of ctx.region.
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
