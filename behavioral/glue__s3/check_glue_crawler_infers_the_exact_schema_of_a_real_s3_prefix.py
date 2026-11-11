"""glue-crawler-infers-the-exact-schema-of-a-real-s3-prefix."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "glue-crawler-infers-the-exact-schema-of-a-real-s3-prefix"
GROUP = 'crawlers'
SERVICES = ['glue', 's3']

# 50 data rows whose three columns are unambiguously an integer, a string and a decimal, so
# a crawler that really reads the bytes must infer bigint/string/double and not default to
# string. The exact byte length is asserted back out of the table's sizeKey parameter.
_CSV = b"id,name,score\n" + b"".join(
    f"{i},name{i},{i}.5\n".encode() for i in range(1, 51))


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A crawler over a prefix this check populated infers the exact schema of those bytes: the
    column names, the inferred types, the classification and the scanned object count."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-behav-gluecrawl-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real",
                                                             "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="rows/people.csv", Body=_CSV)

    role_arn = _create_glue_role(ctx, iam, bucket)

    database = ctx.unique_name("sim2real_behav_gluedb_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": database})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    crawler = ctx.unique_name("sim2real-behav-gluecrawl-")
    _create_crawler(glue, Name=crawler, Role=role_arn, DatabaseName=database,
                    TablePrefix="inferred_",
                    Targets={"S3Targets": [{"Path": f"s3://{bucket}/rows/"}]},
                    Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_crawler(Name=crawler),
                                         f"glue crawler {crawler}"))

    last_crawl = _crawl_to_ready(glue, crawler)
    assert last_crawl.get("Status") == "SUCCEEDED", (
        f"LastCrawl was {last_crawl!r}"
    )

    tables = _get_tables(glue, database)
    for table_name in [t["Name"] for t in tables]:
        ctx.on_cleanup(lambda n=table_name: _retry_delete(
            lambda: glue.delete_table(DatabaseName=database, Name=n),
            f"glue table {database}.{n}"))

    assert len(tables) == 1, (
        f"the crawler created {len(tables)!r} tables: {[t['Name'] for t in tables]!r}"
    )
    table = tables[0]
    columns = table["StorageDescriptor"]["Columns"]
    typed = [(c["Name"], c["Type"]) for c in columns]

    assert [c["Name"] for c in columns] == ["id", "name", "score"], (
        f"inferred columns were {typed!r}, expected the CSV header id/name/score"
    )
    assert [c["Type"] for c in columns] == ["bigint", "string", "double"], (
        f"inferred types were {typed!r}; the crawler did not derive them from the data"
    )
    parameters = table.get("Parameters", {})
    assert parameters.get("classification") == "csv", (
        f"classification was {parameters.get('classification')!r}, expected 'csv'"
    )
    assert parameters.get("skip.header.line.count") == "1", (
        f"skip.header.line.count was {parameters.get('skip.header.line.count')!r}; the "
        f"crawler did not recognise the header row"
    )
    assert parameters.get("sizeKey") == str(len(_CSV)), (
        f"sizeKey was {parameters.get('sizeKey')!r}, but the check uploaded exactly "
        f"{len(_CSV)!r} bytes, so the crawler did not scan the object it was pointed at"
    )
    assert table["StorageDescriptor"]["Location"] == f"s3://{bucket}/rows/", (
        f"the inferred table points at {table['StorageDescriptor']['Location']!r}, not at "
        f"the crawled prefix s3://{bucket}/rows/"
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
