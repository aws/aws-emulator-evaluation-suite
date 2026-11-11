"""import-table-describe-list-workflow."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-table-describe-list-workflow"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ImportTable loads DynamoDB-JSON items from S3 into a new table, reaches COMPLETED with
    ImportedItemCount 3 in DescribeImport and ListImports, and the table holds the imported data;
    after the table is deleted, PutItem fails with ResourceNotFoundException."""
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-imp-bucket-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    items = [
        {"Item": {"pk": {"S": "row-1"}, "value": {"S": "alpha"}}},
        {"Item": {"pk": {"S": "row-2"}, "value": {"S": "beta"}}},
        {"Item": {"pk": {"S": "row-3"}, "value": {"S": "gamma"}}},
    ]
    body = "\n".join(json.dumps(i) for i in items).encode("utf-8")
    key_prefix = "import-data/"
    s3.put_object(Bucket=bucket, Key=f"{key_prefix}items.json", Body=body)

    target_table = ctx.unique_name("sim2real-behav-imp-tbl-")
    import_resp = ddb.import_table(
        S3BucketSource={"S3Bucket": bucket, "S3KeyPrefix": key_prefix},
        InputFormat="DYNAMODB_JSON",
        InputCompressionType="NONE",
        TableCreationParameters={
            "TableName": target_table,
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "BillingMode": "PAY_PER_REQUEST",
        },
    )
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, target_table))
    import_arn = import_resp["ImportTableDescription"]["ImportArn"]
    assert import_resp["ImportTableDescription"]["ImportStatus"] in ("IN_PROGRESS", "COMPLETED")

    described = _poll_until(
        lambda: ddb.describe_import(ImportArn=import_arn)["ImportTableDescription"],
        lambda d: d["ImportStatus"] in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=900,
        interval_s=15,
    )
    assert described["ImportStatus"] == "COMPLETED", f"import did not complete: {described}"
    assert described["ImportedItemCount"] == 3
    assert described["TableArn"] is not None

    listed = ddb.list_imports(TableArn=described["TableArn"])["ImportSummaryList"]
    matching = [i for i in listed if i["ImportArn"] == import_arn]
    assert len(matching) == 1, f"expected import {import_arn} in ListImports, got {listed}"
    assert matching[0]["ImportStatus"] == "COMPLETED"

    _wait_table_active(ddb, target_table)
    ddb.tag_resource(ResourceArn=described["TableArn"], Tags=[{"Key": "sim2real", "Value": CHECK}])
    got = ddb.get_item(TableName=target_table, Key={"pk": {"S": "row-2"}}, ConsistentRead=True)
    assert "Item" in got
    assert got["Item"]["value"]["S"] == "beta"

    _delete_table_retrying(ddb, target_table)
    _wait_table_deleted(ddb, target_table)

    try:
        ddb.put_item(TableName=target_table, Item={"pk": {"S": "row-4"}})
    except ClientError as exc:
        put_err = exc.response.get("Error", {})
    else:
        raise AssertionError(f"PutItem on the deleted table {target_table!r} was ACCEPTED")
    assert put_err.get("Code") == "ResourceNotFoundException", (
        f"expected PutItem on a deleted table to fail with ResourceNotFoundException, "
        f"got {put_err.get('Code')!r}"
    )
    assert put_err.get("Message") == "Requested resource not found", (
        f"expected message 'Requested resource not found', got {put_err.get('Message')!r}"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _wait_table_active(ddb, table_name: str, timeout_s: float = 120) -> None:
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=3,
    )


def _delete_table_retrying(ddb, table_name: str, timeout_s: float = 60) -> None:
    """Retry DeleteTable through the transient ResourceInUseException raised while a just-issued
    TagResource is still propagating ("Table tags are being updated")."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceInUseException":
                raise
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"delete_table did not succeed within {timeout_s}s: {last_exc}")


def _wait_table_deleted(ddb, table_name: str, timeout_s: float = 120) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(5)
    raise AssertionError(f"table not deleted within {timeout_s}s, last status: {last_status!r}")


def _delete_table_ignore(ddb, table_name: str) -> None:
    """Teardown delete: a table already gone is fine; ResourceInUseException (tag propagation, or a
    delete in progress) is retried every 2 s for up to 120 s; any other error raises."""
    deadline = time.monotonic() + 120
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup() -> None:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if keys:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
