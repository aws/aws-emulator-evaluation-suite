"""import-table-lifecycle-to-completed."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-table-lifecycle-to-completed"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ImportTable transitions IN_PROGRESS -> COMPLETED, is visible via DescribeImport and
    ListImports throughout, and the imported table actually contains the source rows."""
    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-behav-imp-bkt-").lower().replace("_", "-")
    _create_bucket(s3, bucket_name, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    key_prefix = "import/"
    # InputFormatOptions.Csv.HeaderList below explicitly supplies the column names, so the
    # source file itself must contain ONLY data rows — a leading "id,val" header line would
    # be ingested as a third (bogus) item and inflate ImportedItemCount past the 2 real rows.
    csv_body = "item-1,alpha\nitem-2,beta\n"
    s3.put_object(Bucket=bucket_name, Key=f"{key_prefix}data.csv", Body=csv_body.encode("utf-8"))

    target_table = ctx.unique_name("sim2real-behav-imp-dst-")
    import_resp = ddb.import_table(
        S3BucketSource={"S3Bucket": bucket_name, "S3KeyPrefix": key_prefix},
        InputFormat="CSV",
        InputFormatOptions={"Csv": {"Delimiter": ",", "HeaderList": ["id", "val"]}},
        TableCreationParameters={
            "TableName": target_table,
            "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
            "BillingMode": "PAY_PER_REQUEST",
        },
    )
    import_arn = import_resp["ImportTableDescription"]["ImportArn"]
    import_status = import_resp["ImportTableDescription"]["ImportStatus"]
    assert import_status in ("IN_PROGRESS", "COMPLETED"), (
        f"expected ImportTable to report IN_PROGRESS or COMPLETED, got {import_status!r}"
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, target_table))

    listed = _poll_until(
        lambda: _list_import_arns(ddb),
        lambda arns: import_arn in arns,
        timeout_s=60,
        interval_s=3,
    )
    assert import_arn in listed, f"expected {import_arn} in ListImports, got {listed}"

    described = _poll_until(
        lambda: ddb.describe_import(ImportArn=import_arn)["ImportTableDescription"],
        lambda desc: desc["ImportStatus"] in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=1200,
        interval_s=20,
    )
    assert described["ImportStatus"] == "COMPLETED", described
    assert described["ImportedItemCount"] == 2, described
    assert described["InputFormat"] == "CSV", (
        f"expected DescribeImport to echo InputFormat=CSV, got {described['InputFormat']!r}"
    )

    _poll_until(
        lambda: ddb.describe_table(TableName=target_table)["Table"]["TableStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )
    table_arn = ddb.describe_table(TableName=target_table)["Table"]["TableArn"]
    ddb.tag_resource(ResourceArn=table_arn, Tags=[{"Key": "sim2real", "Value": CHECK}])

    item1 = ddb.get_item(TableName=target_table, Key={"id": {"S": "item-1"}}).get("Item")
    item2 = ddb.get_item(TableName=target_table, Key={"id": {"S": "item-2"}}).get("Item")
    assert item1 is not None and item1["val"]["S"] == "alpha", f"item-1 not imported correctly: {item1}"
    assert item2 is not None and item2["val"]["S"] == "beta", f"item-2 not imported correctly: {item2}"


def _create_bucket(s3: Any, bucket_name: str, region: str) -> None:
    # us-east-1 is S3's own CreateBucket special case: it is the one region that
    # rejects an explicit LocationConstraint, not a pin of this check to that region.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )


def _empty_and_delete_bucket(s3: Any, bucket_name: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _list_import_arns(ddb: Any) -> list[str]:
    arns: list[str] = []
    kwargs: dict[str, Any] = {}
    while True:
        resp = ddb.list_imports(**kwargs)
        arns.extend(i["ImportArn"] for i in resp.get("ImportSummaryList", []))
        token = resp.get("NextToken")
        if not token:
            return arns
        kwargs["NextToken"] = token


def _safe_delete_table(ddb: Any, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
