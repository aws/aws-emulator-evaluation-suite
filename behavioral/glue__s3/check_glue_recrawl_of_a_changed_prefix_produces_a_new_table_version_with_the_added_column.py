"""glue-recrawl-of-a-changed-prefix-produces-a-new-table-version-with-the-added-column."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "glue-recrawl-of-a-changed-prefix-produces-a-new-table-version-with-the-added-column"
GROUP = 'crawlers'
SERVICES = ['glue', 's3']

_CSV_V1 = b"id,name,score\n" + b"".join(
    f"{i},name{i},{i}.5\n".encode() for i in range(1, 51))
_CSV_V2 = b"id,name,score,region\n" + b"".join(
    f"{i},name{i},{i}.5,eu-{i % 3}\n".encode() for i in range(1, 51))


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Re-crawling changed content forks a new table version: the old one keeps the three-column
    schema, the new one and the live table carry the added column, and each version's sizeKey
    matches the bytes of its own generation.
    """
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-behav-gluerecrawl-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real",
                                                             "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="rows/people.csv", Body=_CSV_V1)

    role_arn = _create_glue_role(ctx, iam, bucket)

    database = ctx.unique_name("sim2real_behav_gluedb_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": database})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    crawler = ctx.unique_name("sim2real-behav-gluerecrawl-")
    _create_crawler(glue, Name=crawler, Role=role_arn, DatabaseName=database,
                    TablePrefix="versioned_",
                    Targets={"S3Targets": [{"Path": f"s3://{bucket}/rows/"}]},
                    SchemaChangePolicy={"UpdateBehavior": "UPDATE_IN_DATABASE",
                                        "DeleteBehavior": "LOG"},
                    Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_crawler(Name=crawler),
                                         f"glue crawler {crawler}"))

    first_crawl = _crawl_to_ready(glue, crawler)
    table_name = "versioned_rows"
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: glue.delete_table(DatabaseName=database, Name=table_name),
        f"glue table {database}.{table_name}"))
    after_first = glue.get_table(DatabaseName=database, Name=table_name)["Table"]
    first_version = after_first["VersionId"]
    first_columns = [c["Name"] for c in after_first["StorageDescriptor"]["Columns"]]

    # The one change: the same object gains a fourth column.
    s3.put_object(Bucket=bucket, Key="rows/people.csv", Body=_CSV_V2)
    second_crawl = _crawl_to_ready(glue, crawler)

    live = glue.get_table(DatabaseName=database, Name=table_name)["Table"]
    live_version = live["VersionId"]
    live_columns = [c["Name"] for c in live["StorageDescriptor"]["Columns"]]

    versions = []
    for page in glue.get_paginator("get_table_versions").paginate(DatabaseName=database,
                                                                 TableName=table_name):
        versions.extend(page["TableVersions"])
    by_id = {v["VersionId"]: v["Table"] for v in versions}
    ordered = sorted(by_id, key=int)

    crawl_statuses = [first_crawl.get("Status"), second_crawl.get("Status")]
    assert crawl_statuses == ["SUCCEEDED", "SUCCEEDED"], (
        f"crawl statuses were {crawl_statuses!r}; first={first_crawl!r} "
        f"second={second_crawl!r}"
    )
    assert first_columns == ["id", "name", "score"], (
        f"the first crawl inferred {first_columns!r}, expected the three-column CSV"
    )
    assert len(ordered) == 2, (
        f"expected 2 table versions after two crawls of changed content, got "
        f"{ordered!r}"
    )
    older, newer = ordered
    older_columns = [c["Name"] for c in by_id[older]["StorageDescriptor"]["Columns"]]
    newer_columns = [c["Name"] for c in by_id[newer]["StorageDescriptor"]["Columns"]]
    assert older_columns == ["id", "name", "score"], (
        f"version {older!r} columns are {older_columns!r}; an archived version must still "
        f"describe the content that produced it"
    )
    assert newer_columns == ["id", "name", "score", "region"], (
        f"version {newer!r} columns are {newer_columns!r}, expected the added region column"
    )
    assert live_columns == newer_columns and live_version == newer, (
        f"GetTable returned version {live_version!r} with {live_columns!r}, but the newest "
        f"version is {newer!r} with {newer_columns!r}"
    )
    assert older == first_version, (
        f"the first crawl reported VersionId {first_version!r} but the archived older "
        f"version is {older!r}"
    )
    assert by_id[older]["Parameters"]["sizeKey"] == str(len(_CSV_V1)), (
        f"version {older!r} records sizeKey "
        f"{by_id[older]['Parameters'].get('sizeKey')!r}, but generation 1 was exactly "
        f"{len(_CSV_V1)!r} bytes, so that version was not derived from it"
    )
    assert by_id[newer]["Parameters"]["sizeKey"] == str(len(_CSV_V2)), (
        f"version {newer!r} records sizeKey "
        f"{by_id[newer]['Parameters'].get('sizeKey')!r}, but generation 2 was exactly "
        f"{len(_CSV_V2)!r} bytes"
    )


# ===== helpers =====

def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_glue_role(ctx, iam, bucket: str) -> str:
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "glue.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]})
    role = ctx.unique_name("sim2real-behav-gluerole-")
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: iam.delete_role(RoleName=role),
                                         f"iam role {role}"))
    managed = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role, PolicyArn=managed)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.detach_role_policy(RoleName=role, PolicyArn=managed),
        f"detach {managed} from {role}"))
    iam.put_role_policy(RoleName=role, PolicyName="sim2real-s3", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                       "Resource": f"arn:aws:s3:::{bucket}/*"},
                      {"Effect": "Allow", "Action": ["s3:ListBucket"],
                       "Resource": f"arn:aws:s3:::{bucket}"}]}))
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-s3"),
        f"inline policy on {role}"))
    return arn


def _create_crawler(glue, *, timeout_s: float = 180.0, **kwargs) -> None:
    """CreateCrawler validates synchronously that Glue can assume the role, so it raises
    InvalidInputException while IAM propagation is still in flight; retry until it clears.
    IAM exposes no condition that reports a role has become assumable by a service."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidInputException" \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _crawl_to_ready(glue, crawler: str, *, timeout_s: float = 600.0) -> dict:
    glue.start_crawler(Name=crawler)
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        described = glue.get_crawler(Name=crawler)["Crawler"]
        state = described.get("State")
        if state == "READY":
            return described.get("LastCrawl", {})
        time.sleep(5)
    raise AssertionError(
        f"crawler {crawler!r} did not return to READY within {timeout_s}s "
        f"(last state {state!r})")


def _get_tables(glue, database: str) -> list:
    tables = []
    for page in glue.get_paginator("get_tables").paginate(DatabaseName=database):
        tables.extend(page["TableList"])
    return sorted(tables, key=lambda t: t["Name"])


def _retry_delete(fn: Callable[[], Any], label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions:
    a throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "NoSuchBucket",
            "ResourceNotFoundException", "404")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "DeleteConflict", "CrawlerRunningException", "RequestLimitExceeded")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)
        except Exception as exc:  # noqa: BLE001 - re-raised
            raise RuntimeError(f"{label}: {type(exc).__name__}: {exc}") from exc


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    from botocore.exceptions import ClientError

    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    _retry_delete(lambda: s3.delete_bucket(Bucket=bucket), f"s3 bucket {bucket}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
