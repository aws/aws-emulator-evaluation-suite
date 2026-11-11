"""glue-crawler-role-denied-s3-read-catalogues-no-table."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "glue-crawler-role-denied-s3-read-catalogues-no-table"
GROUP = 'overly-permissive'
SERVICES = ['glue', 's3']

_CSV = b"id,name,score\n" + b"".join(
    f"{i},name{i},{i}.5\n".encode() for i in range(1, 51))


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A crawler whose role is denied s3:GetObject reports LastCrawl SUCCEEDED with no error yet
    catalogues no table, while an identical crawler whose role can read the prefix infers the
    full schema."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-behav-gluecrawldenied-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real",
                                                             "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="rows/people.csv", Body=_CSV)

    # The one broken thing: no bucket policy statement at all on the denied role.
    denied_arn = _create_glue_role(ctx, iam, bucket, grant_bucket_read=False)
    allowed_arn = _create_glue_role(ctx, iam, bucket, grant_bucket_read=True)

    database = ctx.unique_name("sim2real_behav_gluedb_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": database})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    target = {"S3Targets": [{"Path": f"s3://{bucket}/rows/"}]}
    denied_crawler = ctx.unique_name("sim2real-behav-gluecrawldenied-")
    _create_crawler(glue, Name=denied_crawler, Role=denied_arn, DatabaseName=database,
                    TablePrefix="denied_", Targets=target, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_crawler(Name=denied_crawler),
                                         f"glue crawler {denied_crawler}"))
    control_crawler = ctx.unique_name("sim2real-behav-gluecrawlok-")
    _create_crawler(glue, Name=control_crawler, Role=allowed_arn, DatabaseName=database,
                    TablePrefix="control_", Targets=target, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_crawler(Name=control_crawler),
                                         f"glue crawler {control_crawler}"))

    denied_crawl = _crawl_to_ready(glue, denied_crawler)

    assert denied_crawl.get("Status") == "SUCCEEDED", (
        f"the crawl under a role with no read access on the bucket reported "
        f"{denied_crawl.get('Status')!r}; real AWS reports SUCCEEDED here: {denied_crawl!r}"
    )
    assert denied_crawl.get("ErrorMessage") is None, (
        f"real AWS reports no ErrorMessage for an unreadable target, but LastCrawl carried "
        f"{denied_crawl.get('ErrorMessage')!r}"
    )
    tables_after_denied = [t["Name"] for t in _get_tables(glue, database)]
    for name in tables_after_denied:
        ctx.on_cleanup(lambda n=name: _retry_delete(
            lambda: glue.delete_table(DatabaseName=database, Name=n),
            f"glue table {database}.{n}"))
    assert tables_after_denied == [], (
        f"the failed crawl still catalogued {tables_after_denied!r}; the database must be "
        f"untouched"
    )

    control_crawl = _crawl_to_ready(glue, control_crawler)
    assert control_crawl.get("Status") == "SUCCEEDED", (
        f"the positive control crawl over the same prefix reported {control_crawl!r}"
    )
    tables_after_control = _get_tables(glue, database)
    for name in [t["Name"] for t in tables_after_control]:
        ctx.on_cleanup(lambda n=name: _retry_delete(
            lambda: glue.delete_table(DatabaseName=database, Name=n),
            f"glue table {database}.{n}"))
    assert [t["Name"] for t in tables_after_control] == ["control_rows"], (
        f"the control crawl catalogued {[t['Name'] for t in tables_after_control]!r}, "
        f"expected exactly ['control_rows']"
    )
    control_columns = [(c["Name"], c["Type"])
                       for c in tables_after_control[0]["StorageDescriptor"]["Columns"]]
    assert control_columns == [("id", "bigint"), ("name", "string"), ("score", "double")], (
        f"the control crawl inferred {control_columns!r}, so the prefix was readable all "
        f"along and only the denied role's policy suppressed it"
    )


# ===== helpers =====

def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_glue_role(ctx, iam, bucket: str, *, grant_bucket_read: bool) -> str:
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
    if grant_bucket_read:
        iam.put_role_policy(RoleName=role, PolicyName="sim2real-s3",
                            PolicyDocument=json.dumps({
                                "Version": "2012-10-17",
                                "Statement": [
                                    {"Effect": "Allow", "Action": ["s3:GetObject"],
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
