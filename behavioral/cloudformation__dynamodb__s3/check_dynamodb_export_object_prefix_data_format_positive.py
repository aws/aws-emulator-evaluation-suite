"""dynamodb-export-object-prefix-data-format-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "dynamodb-export-object-prefix-data-format-positive"
GROUP = "data-format"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """The S3Prefix given to export_table_to_point_in_time is faithfully reflected in
    every resulting object key (manifest-summary.json, manifest-files.json, and the
    data file) under that exact prefix."""
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    table_name = ctx.unique_name("sim2real-ddbpfx-")
    table_arn = _create_table(ctx, table_name)
    _enable_pitr(ctx, table_name)
    ddb.put_item(TableName=table_name, Item={"pk": {"S": "item-0"}})

    bucket = ctx.unique_name("sim2real-ddbpfx-dst-")
    _create_bucket(ctx, bucket)

    prefix = "custom/nested-prefix"
    export_desc = _export_with_retry(
        ddb,
        TableArn=table_arn,
        S3Bucket=bucket,
        S3Prefix=prefix,
        ExportFormat="DYNAMODB_JSON",
    )["ExportDescription"]
    final = _wait_export_terminal(ctx, export_desc["ExportArn"], timeout_s=900)
    assert final["ExportStatus"] == "COMPLETED", (
        f"export did not complete: status={final['ExportStatus']} "
        f"failure={final.get('FailureCode')}/{final.get('FailureMessage')}"
    )
    assert final.get("S3Prefix") == prefix, f"expected S3Prefix {prefix!r}, export reports {final.get('S3Prefix')!r}"

    manifest_key = final["ExportManifest"]
    assert manifest_key.startswith(prefix + "/"), f"manifest key {manifest_key!r} not under prefix {prefix!r}"
    assert "/AWSDynamoDB/" in manifest_key, f"manifest key {manifest_key!r} missing the /AWSDynamoDB/ export layout segment"

    s3.head_object(Bucket=bucket, Key=manifest_key)

    files_manifest_key = manifest_key.replace("manifest-summary.json", "manifest-files.json")
    assert files_manifest_key.startswith(prefix + "/"), (
        f"files manifest key {files_manifest_key!r} not under prefix {prefix!r}"
    )
    body = s3.get_object(Bucket=bucket, Key=files_manifest_key)["Body"].read().decode("utf-8")
    first_line = next(line for line in body.splitlines() if line.strip())
    data_file_key = json.loads(first_line)["dataFileS3Key"]
    assert data_file_key.startswith(prefix + "/"), f"data file key {data_file_key!r} not under prefix {prefix!r}"
    s3.head_object(Bucket=bucket, Key=data_file_key)

    # every object actually written to the bucket lives under the requested prefix
    listing = s3.list_objects_v2(Bucket=bucket)
    all_keys = [o["Key"] for o in listing.get("Contents", [])]
    assert all_keys, "export completed but wrote no objects"
    assert all(k.startswith(prefix + "/") for k in all_keys), f"objects outside prefix: {all_keys}"


def _create_table(ctx: Any, table_name: str) -> str:
    ddb = ctx.client("dynamodb")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return ddb.describe_table(TableName=table_name)["Table"]["TableArn"]


def _enable_pitr(ctx: Any, table_name: str, timeout_s: float = 60.0) -> None:
    ddb = ctx.client("dynamodb")
    _update_backups_when_ready(
        ctx,
        ddb,
        TableName=table_name,
        PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
    )
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_continuous_backups(TableName=table_name)[
            "ContinuousBackupsDescription"
        ]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]
        if status == "ENABLED":
            return
        time.sleep(2)
    raise AssertionError("PITR never reached ENABLED")


def _export_with_retry(ddb: Any, timeout_s: float = 90.0, **kwargs: Any) -> dict:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return ddb.export_table_to_point_in_time(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "PointInTimeRecoveryUnavailableException":
                last_exc = e
                time.sleep(3)
                continue
            raise
    raise last_exc


def _wait_export_terminal(ctx: Any, export_arn: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> dict:
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    desc: dict = {}
    while time.monotonic() < deadline:
        desc = ddb.describe_export(ExportArn=export_arn)["ExportDescription"]
        if desc["ExportStatus"] != "IN_PROGRESS":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"export did not reach a terminal state within {timeout_s}s: {desc}")


def _create_bucket(ctx: Any, name: str) -> str:
    s3 = ctx.client("s3")
    kwargs: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx: Any, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _update_backups_when_ready(ctx, ddb, **kwargs) -> None:
    """UpdateContinuousBackups, retried while AWS still initialises a new table's backups."""
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else min(120.0, left))
    while True:
        try:
            ddb.update_continuous_backups(**kwargs)
            return
        except ddb.exceptions.ContinuousBackupsUnavailableException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
