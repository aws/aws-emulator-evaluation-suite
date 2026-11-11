"""import-table-malformed-item-reports-exact-failure."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-table-malformed-item-reports-exact-failure"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ImportTable on a DYNAMODB_JSON source holding one item with a malformed attribute value
    ends FAILED with ErrorCount 1 and AWS's exact FailureCode and FailureMessage, while the
    item preceding the malformed one is imported and readable."""
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-imp-bad-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    # DYNAMODB_JSON, one line per item; the second item's "value" is typed N but holds a
    # non-numeric string, which AWS rejects as a malformed attribute value.
    lines = [
        {"Item": {"pk": {"S": "row-1"}, "value": {"S": "alpha"}}},
        {"Item": {"pk": {"S": "row-2"}, "value": {"N": "not-a-number"}}},
    ]
    body = "\n".join(json.dumps(line) for line in lines).encode("utf-8")
    key_prefix = "import-data/"
    s3.put_object(Bucket=bucket, Key=f"{key_prefix}items.json", Body=body)

    target_table = ctx.unique_name("sim2real-behav-imp-bad-tbl-")
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
    assert import_resp["ImportTableDescription"]["ImportStatus"] in ("IN_PROGRESS", "COMPLETED", "FAILED"), (
        f"unexpected initial ImportStatus {import_resp['ImportTableDescription']['ImportStatus']!r}"
    )

    described = _poll_until(
        lambda: ddb.describe_import(ImportArn=import_arn)["ImportTableDescription"],
        lambda d: d["ImportStatus"] in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=900,
        interval_s=15,
    )
    assert described["ImportStatus"] == "FAILED", (
        f"expected an import with one malformed item to end FAILED, got {described['ImportStatus']!r}"
    )
    assert described["ErrorCount"] == 1, f"expected ErrorCount 1, got {described['ErrorCount']!r}"
    assert described["FailureCode"] == "ItemValidationError", (
        f"expected FailureCode ItemValidationError, got {described.get('FailureCode')!r}"
    )
    expected_message = (
        "Some of the items failed validation checks and were not imported. "
        "Please check CloudWatch error logs for more details."
    )
    assert described["FailureMessage"] == expected_message, (
        f"expected message {expected_message!r}, got {described.get('FailureMessage')!r}"
    )

    _wait_table_active(ddb, target_table)
    ddb.tag_resource(ResourceArn=described["TableArn"], Tags=[{"Key": "sim2real", "Value": CHECK}])
    got = ddb.get_item(TableName=target_table, Key={"pk": {"S": "row-1"}}, ConsistentRead=True)
    assert got.get("Item") == {"pk": {"S": "row-1"}, "value": {"S": "alpha"}}, (
        f"expected row-1 to have imported correctly, got {got.get('Item')!r}"
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
