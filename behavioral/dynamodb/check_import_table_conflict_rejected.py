"""import-table-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-table-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Once an in-progress import's destination table exists, a second ImportTable naming it fails
    synchronously with ResourceInUseException "Table already exists"; ListImports tracks only the
    first import, which stays IN_PROGRESS or COMPLETED."""
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-behav-imp-")
    _create_bucket(ctx, bucket_name)
    key = "import-data/items.json"
    body = '{"Item":{"pk":{"S":"item-1"}}}\n{"Item":{"pk":{"S":"item-2"}}}\n'
    s3.put_object(Bucket=bucket_name, Key=key, Body=body.encode("utf-8"))

    dest_table_name = ctx.unique_name("sim2real-behav-imported-")
    creation_params = {
        "TableName": dest_table_name,
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
    }
    s3_source = {"S3Bucket": bucket_name, "S3KeyPrefix": "import-data/"}

    first = ddb.import_table(
        S3BucketSource=s3_source,
        InputFormat="DYNAMODB_JSON",
        TableCreationParameters=creation_params,
    )["ImportTableDescription"]
    first_import_arn = first["ImportArn"]
    assert first["ImportStatus"] == "IN_PROGRESS", (
        f"expected the first ImportTable to be accepted as IN_PROGRESS, "
        f"got {first['ImportStatus']!r}"
    )

    # The import creates its table asynchronously; a second call before it exists starts an
    # independent import instead of colliding, so wait for the table first.
    _wait_table_exists(ctx, dest_table_name)
    dest_table_arn = ddb.describe_table(TableName=dest_table_name)["Table"]["TableArn"]

    def _cleanup_import_artifacts():
        try:
            _wait_import_terminal(ctx, first_import_arn, timeout_s=420, interval_s=5)
        except AssertionError:
            pass
        try:
            ddb.delete_table(TableName=dest_table_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ResourceNotFoundException",
                "TableNotFoundException",
            ):
                raise

    # Registered before the assertions so a failure still deletes the table.
    ctx.on_cleanup(_cleanup_import_artifacts)

    try:
        second = ddb.import_table(
            S3BucketSource=s3_source,
            InputFormat="DYNAMODB_JSON",
            TableCreationParameters=creation_params,
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
        assert code == "ResourceInUseException", (
            f"expected the conflicting second ImportTable to be rejected with "
            f"ResourceInUseException, got {code!r}: {message!r}"
        )
        assert message == f"Table already exists: {dest_table_name}", (
            f"expected the ResourceInUseException to name the existing table "
            f"{dest_table_name!r}, got {message!r}"
        )
    else:
        raise AssertionError(
            f"expected the conflicting second ImportTable to raise ResourceInUseException, "
            f"but it was accepted: {second['ImportTableDescription']}"
        )

    imports_for_table = ddb.list_imports(TableArn=dest_table_arn)["ImportSummaryList"]
    assert [i["ImportArn"] for i in imports_for_table] == [first_import_arn], (
        f"expected only the first import to be tracked against {dest_table_name!r}, "
        f"got {imports_for_table}"
    )

    still_tracked = ddb.describe_import(ImportArn=first_import_arn)["ImportTableDescription"]
    assert still_tracked["ImportArn"] == first_import_arn, (
        f"expected DescribeImport to still track {first_import_arn!r}, "
        f"got {still_tracked['ImportArn']!r}"
    )
    assert still_tracked["ImportStatus"] in ("IN_PROGRESS", "COMPLETED"), (
        f"expected the first import to still be IN_PROGRESS or COMPLETED, "
        f"got {still_tracked['ImportStatus']!r}"
    )


def _create_bucket(ctx, bucket_name):
    s3 = ctx.client("s3")
    # us-east-1 is the one region S3 CreateBucket rejects a LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

    def _delete_bucket():
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket_name,
                Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_delete_bucket)


def _wait_import_terminal(ctx, import_arn, timeout_s=420, interval_s=5):
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    last = None
    terminal = {"COMPLETED", "CANCELLED", "FAILED"}
    while time.monotonic() < deadline:
        desc = ddb.describe_import(ImportArn=import_arn)["ImportTableDescription"]
        last = desc["ImportStatus"]
        if last in terminal:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"import {import_arn} never reached a terminal state, last={last}")


def _wait_table_exists(ctx, table_name, timeout_s=120, interval_s=3):
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            ddb.describe_table(TableName=table_name)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never came into existence, last error: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
