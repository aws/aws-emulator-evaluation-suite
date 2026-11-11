"""list-imports-pagination-consistent-order."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-imports-pagination-consistent-order"
GROUP = "ordering"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListImports, paginated one item per page via NextToken, returns each
    import exactly once and in a stable order across independent full
    traversals (no duplication, no reordering between calls)."""
    bucket = _create_bucket(ctx)

    created_arns = []
    created_tables = []
    for i in range(2):
        key = f"import-source-{i}.csv"
        _upload_csv(ctx, bucket, key)
        table_name = ctx.unique_name(f"sim2real-behav-limp-{i}-")
        resp = ctx.client("dynamodb").import_table(
            S3BucketSource={"S3Bucket": bucket, "S3KeyPrefix": key},
            InputFormat="CSV",
            TableCreationParameters={
                "TableName": table_name,
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "BillingMode": "PAY_PER_REQUEST",
            },
        )
        created_arns.append(resp["ImportTableDescription"]["ImportArn"])
        created_tables.append(table_name)
        ctx.on_cleanup(lambda t=table_name: _cleanup_import_table(ctx, t))

    first_pass = _list_all_imports(ctx, page_size=1)
    second_pass = _list_all_imports(ctx, page_size=1)

    assert len(first_pass) == len(set(first_pass)), (
        f"ListImports returned a duplicate import ARN across pages: {first_pass}"
    )
    missing = set(created_arns) - set(first_pass)
    assert not missing, f"imports missing from paginated listing: {missing}"
    assert first_pass == second_pass, (
        "ListImports pagination order was not stable across two full traversals: "
        f"{first_pass} != {second_pass}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ddbimport-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "list-imports-pagination-consistent-order"}]},
    )
    return name


def _upload_csv(ctx, bucket: str, key: str) -> None:
    s3 = ctx.client("s3")
    body = "pk,val\nrow-1,1\nrow-2,2\n"
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))


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


def _cleanup_import_table(ctx, table_name: str, timeout_s: float = 240.0, interval_s: float = 5.0) -> None:
    """Import-created tables can be CREATING/UPDATING while the import runs;
    wait for a deletable state (best-effort) before deleting."""
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            desc = ddb.describe_table(TableName=table_name)
        except ddb.exceptions.ResourceNotFoundException:
            return
        status = desc["Table"]["TableStatus"]
        if status == "ACTIVE":
            break
        time.sleep(interval_s)
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _list_all_imports(ctx, page_size: int = 1) -> list[str]:
    ddb = ctx.client("dynamodb")
    arns: list[str] = []
    token: Any = None
    for _ in range(200):  # hard cap to avoid infinite loop on a broken NextToken
        kwargs: dict[str, Any] = {"PageSize": page_size}
        if token:
            kwargs["NextToken"] = token
        resp = ddb.list_imports(**kwargs)
        arns.extend(s["ImportArn"] for s in resp.get("ImportSummaryList", []))
        token = resp.get("NextToken")
        if not token:
            break
    return arns


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
