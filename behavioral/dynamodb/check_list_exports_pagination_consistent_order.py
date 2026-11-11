"""list-exports-pagination-consistent-order."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-exports-pagination-consistent-order"
GROUP = "ordering"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExports, paginated one item per page via NextToken, returns each
    export exactly once, in the documented reverse-alphanumeric-by-ExportArn
    order, and that order is stable across independent full traversals."""
    table_name, table_arn = _create_table(ctx)
    bucket = _create_bucket(ctx)
    _enable_pitr(ctx, table_name)

    created_arns = []
    for _ in range(3):
        resp = ctx.client("dynamodb").export_table_to_point_in_time(
            TableArn=table_arn, S3Bucket=bucket
        )
        created_arns.append(resp["ExportDescription"]["ExportArn"])
        # Avoid requesting two exports at the exact same point in time, which
        # DynamoDB can reject as a conflicting export request.
        time.sleep(1.5)

    # Poll the paginated listing (bounded) until every created export is visible in it.
    deadline = time.monotonic() + 120.0
    while True:
        first_pass = _list_all_exports(ctx, table_arn, page_size=1)
        if set(created_arns) <= set(first_pass) or time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    second_pass = _list_all_exports(ctx, table_arn, page_size=1)

    assert len(first_pass) == len(set(first_pass)), (
        f"ListExports returned a duplicate export ARN across pages: {first_pass}"
    )
    missing = set(created_arns) - set(first_pass)
    assert not missing, f"exports missing from paginated listing: {missing}"
    assert first_pass == second_pass, (
        "ListExports pagination order was not stable across two full traversals: "
        f"{first_pass} != {second_pass}"
    )
    # ListExports is documented to return results "in reverse alphanumeric
    # order of ExportArn" - verify the paginated traversal actually honors
    # that documented ordering, not just some internal-but-stable order.
    assert first_pass == sorted(first_pass, reverse=True), (
        f"ListExports pages were not in reverse-alphanumeric ExportArn order: {first_pass}"
    )


def _create_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-lexp-")
    resp = ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = resp["TableDescription"]["TableArn"]
    return name, arn


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ddbexport-").lower().replace("_", "-")
    region = ctx.region
    # us-east-1 is CreateBucket's own historical default region, and is the one region
    # where passing a LocationConstraint at all raises InvalidLocationConstraint.
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-behav", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket,
                    Delete={
                        "Objects": [
                            {"Key": o["Key"], "VersionId": o["VersionId"]} for o in objs
                        ]
                    },
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _enable_pitr(ctx, table_name: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> None:
    ddb = ctx.client("dynamodb")
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    # A just-ACTIVE table is still initialising its backups: retry the documented "retry later" error.
    while True:
        try:
            ddb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            break
        except ClientError as exc:
            if (exc.response["Error"]["Code"] != "ContinuousBackupsUnavailableException"
                    or time.monotonic() >= deadline):
                raise
            time.sleep(2)
    while time.monotonic() < deadline:
        resp = ddb.describe_continuous_backups(TableName=table_name)
        status = resp["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"][
            "PointInTimeRecoveryStatus"
        ]
        if status == "ENABLED":
            return
        time.sleep(interval_s)
    raise AssertionError("PITR did not reach ENABLED within the bounded wait")


def _list_all_exports(ctx, table_arn: str, page_size: int = 1) -> list[str]:
    ddb = ctx.client("dynamodb")
    arns: list[str] = []
    token: Any = None
    for _ in range(200):  # hard cap to avoid infinite loop on a broken NextToken
        kwargs: dict[str, Any] = {"TableArn": table_arn, "MaxResults": page_size}
        if token:
            kwargs["NextToken"] = token
        resp = ddb.list_exports(**kwargs)
        arns.extend(s["ExportArn"] for s in resp.get("ExportSummaries", []))
        token = resp.get("NextToken")
        if not token:
            break
    return arns


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
