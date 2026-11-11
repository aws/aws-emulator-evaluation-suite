"""dynamodb-export-table-to-s3-positive."""
from __future__ import annotations

import gzip
import io
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "dynamodb-export-table-to-s3-positive"
GROUP = "event-propagation"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """export_table_to_point_in_time with an S3 target writes a full manifest + data
    file set into the destination bucket, and the decoded item set in those data files
    is exactly what the table held — not just a status word and a non-empty object."""
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    table_name = ctx.unique_name("sim2real-ddbexp-")
    table_arn = _create_table(ctx, table_name)
    _enable_pitr(ctx, table_name)
    expected_items = set()
    for i in range(3):
        item = {"pk": {"S": f"item-{i}"}, "val": {"N": str(i)}}
        ddb.put_item(TableName=table_name, Item=item)
        expected_items.add(json.dumps(item, sort_keys=True))

    bucket = ctx.unique_name("sim2real-ddbexp-dst-")
    _create_bucket(ctx, bucket)

    export_desc = _export_with_retry(
        ddb,
        TableArn=table_arn,
        S3Bucket=bucket,
        ExportFormat="DYNAMODB_JSON",
    )["ExportDescription"]
    export_arn = export_desc["ExportArn"]

    final = _wait_export_terminal(ctx, export_arn, timeout_s=900)
    assert final["ExportStatus"] == "COMPLETED", (
        f"export did not complete: status={final['ExportStatus']} "
        f"failure={final.get('FailureCode')}/{final.get('FailureMessage')}"
    )

    manifest_key = final["ExportManifest"]
    summary = json.loads(s3.get_object(Bucket=bucket, Key=manifest_key)["Body"].read())
    assert summary["itemCount"] == 3, (
        f"manifest itemCount disagrees with the table: {summary['itemCount']!r}, expected 3"
    )

    files_manifest_key = summary["manifestFilesS3Key"]
    files_body = s3.get_object(Bucket=bucket, Key=files_manifest_key)["Body"].read().decode("utf-8")
    entries = [json.loads(line) for line in files_body.splitlines() if line.strip()]
    data_keys = [e["dataFileS3Key"] for e in entries]
    assert data_keys, "export wrote no data files"
    assert sum(e["itemCount"] for e in entries) == 3, (
        f"per-data-file itemCounts do not partition the table: "
        f"{[e['itemCount'] for e in entries]!r} over 3 items"
    )

    decoded_items = set()
    for key in data_keys:
        blob = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        text = gzip.GzipFile(fileobj=io.BytesIO(blob)).read().decode("utf-8")
        for line in text.splitlines():
            if line.strip():
                decoded_items.add(json.dumps(json.loads(line)["Item"], sort_keys=True))
    assert decoded_items == expected_items, (
        f"exported items differ from what was written to the table: "
        f"{sorted(decoded_items ^ expected_items)!r}"
    )


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
    ddb.update_continuous_backups(
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
    """export_table_to_point_in_time, retrying the transient window right after PITR
    is reported ENABLED but the backend hasn't caught up yet."""
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
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
