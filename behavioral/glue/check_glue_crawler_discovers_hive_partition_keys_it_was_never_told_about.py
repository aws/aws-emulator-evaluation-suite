"""glue-crawler-discovers-hive-partition-keys-it-was-never-told-about."""
from __future__ import annotations

import json
import time
from typing import Any, Callable
from urllib.parse import urlparse

from behavioral_harness import tags

CHECK = "glue-crawler-discovers-hive-partition-keys-it-was-never-told-about"
GROUP = 'crawlers'
SERVICES = ["glue"]

# One crawl over four tiny CSV objects. Measured start-to-READY for this shape is 70-160 s,
# and the crawler cannot start until the role this check created has become assumable, which
# Glue surfaces as a failed crawl rather than a StartCrawler error. This deadline is a hard
# cap shared by every wait below, so the check can never outlive its wrapper.
_TOTAL_DEADLINE_S = 900.0

_DTS = ("2026-03-01", "2026-03-02")
_REGIONS = ("emea", "us")
#: Every (dt, region) leaf the check uploads, in the order a partition-key list must report.
_LEAVES = tuple((dt, region) for dt in _DTS for region in _REGIONS)

#: The crawler is told nothing about the schema. These are the column names and the types the
#: crawl has to DERIVE from the bytes: an integer literal, a quoted-free string, a decimal.
_EXPECTED_COLUMNS = [("id", "bigint"), ("name", "string"), ("score", "double")]
_ROWS_PER_LEAF = 25


def _leaf_csv(dt: str, region: str) -> bytes:
    lines = [f"{i},{region}-{i},{i}.5" for i in range(1, _ROWS_PER_LEAF + 1)]
    return ("id,name,score\n" + "\n".join(lines) + "\n").encode()


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A crawler given only an S3 path derives the Hive partition keys (dt, region; outer-first,
    not data columns), the inferred column types, and one partition per leaf directory pointing
    at the uploaded prefix: partition discovery is a property of the directory tree, not a file."""
    left = ctx.time_left()
    deadline = time.monotonic() + (_TOTAL_DEADLINE_S if left is None else min(_TOTAL_DEADLINE_S, left))
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-behav-gluecrwl-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    uploaded = {}
    for dt, region in _LEAVES:
        key = f"data/dt={dt}/region={region}/rows.csv"
        s3.put_object(Bucket=bucket, Key=key, Body=_leaf_csv(dt, region))
        uploaded[(dt, region)] = key

    database = ctx.unique_name("sim2real_behav_gluecrwl_")
    glue.create_database(DatabaseInput={"Name": database,
                                       "Description": f"SimParity {CHECK}"})
    # DeleteDatabase cascades to the tables and partitions the CRAWLER creates, which is the
    # only handle this check has on them: it never learns their names before the crawl.
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    before = _list_table_names(glue, database)
    assert before == [], (
        f"the database already held tables {before!r} before the crawl, so a table found "
        f"afterwards would not be evidence the crawler created it"
    )

    role_arn = _create_glue_role(ctx, iam, bucket)

    crawler = ctx.unique_name("sim2real-behav-gluecrwl-")
    _create_crawler(glue, deadline=min(deadline, time.monotonic() + 120.0),
        Name=crawler, Role=role_arn, DatabaseName=database,
        Description=f"SimParity {CHECK}",
        Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
        Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_crawler(Name=crawler),
                                         f"glue crawler {crawler}"))

    last = _crawl_to_ready(glue, crawler, deadline=deadline)
    assert last.get("Status") == "SUCCEEDED", (
        f"the crawl ended {last.get('Status')!r}: {last.get('ErrorMessage')!r}"
    )

    # --- the table the crawl created ------------------------------------------------------
    names = _list_table_names(glue, database)
    assert names == ["data"], (
        f"the crawl created tables {names!r}; one table named after the crawled folder "
        f"('data') was expected"
    )
    table = glue.get_table(DatabaseName=database, Name="data")["Table"]

    # --- the partition keys nobody declared -----------------------------------------------
    keys = [(k["Name"], k["Type"]) for k in table.get("PartitionKeys", [])]
    assert keys == [("dt", "string"), ("region", "string")], (
        f"the crawl reported partition keys {keys!r}; the directory layout is "
        f"dt=<value>/region=<value>/, so outer-first ('dt', 'string') then "
        f"('region', 'string') was expected"
    )

    # --- the data columns, and their inferred types ----------------------------------------
    columns = [(c["Name"], c["Type"]) for c in table["StorageDescriptor"]["Columns"]]
    assert columns == _EXPECTED_COLUMNS, (
        f"the crawl inferred data columns {columns!r} from the uploaded CSV, expected "
        f"{_EXPECTED_COLUMNS!r}"
    )
    overlap = {name for name, _ in columns} & {"dt", "region"}
    assert overlap == set(), (
        f"the crawl reported {sorted(overlap)!r} as both a data column and a partition key; "
        f"a Hive partition value lives in the path, not in the object"
    )
    assert table["Parameters"].get("classification") == "csv", (
        f"the crawl classified the objects as "
        f"{table['Parameters'].get('classification')!r}, expected 'csv'"
    )
    assert table["StorageDescriptor"]["Location"].rstrip("/") == \
        f"s3://{bucket}/data".rstrip("/"), (
        f"the table points at {table['StorageDescriptor']['Location']!r}, expected "
        f"s3://{bucket}/data/"
    )

    # --- one partition per leaf directory --------------------------------------------------
    partitions = _list_partitions(glue, database, "data")
    values = sorted(tuple(p["Values"]) for p in partitions)
    assert values == sorted(_LEAVES), (
        f"the crawl registered partitions {values!r}, expected one per uploaded leaf "
        f"{sorted(_LEAVES)!r}"
    )
    for part in partitions:
        dt, region = part["Values"]
        location = part["StorageDescriptor"]["Location"]
        expected = f"s3://{bucket}/data/dt={dt}/region={region}"
        assert location.rstrip("/") == expected, (
            f"partition {(dt, region)!r} points at {location!r}, expected {expected!r}"
        )
        parsed = urlparse(location)
        assert parsed.netloc == bucket, (
            f"partition {(dt, region)!r} points at bucket {parsed.netloc!r}, expected "
            f"{bucket!r}"
        )
        prefix = parsed.path.lstrip("/").rstrip("/") + "/"
        assert uploaded[(dt, region)].startswith(prefix), (
            f"partition {(dt, region)!r} points at {prefix!r}, which does not contain the "
            f"object this check uploaded at {uploaded[(dt, region)]!r}"
        )


# ===== helpers =====

def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_glue_role(ctx, iam, bucket: str) -> str:
    """Create a role Glue can assume, with read on exactly one bucket."""
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "glue.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]})
    role = ctx.unique_name("sim2real-behav-gluerole-")
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                          Description=f"SimParity {CHECK}",
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
                      {"Effect": "Allow",
                       "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                       "Resource": f"arn:aws:s3:::{bucket}"}]}))
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-s3"),
        f"inline policy on {role}"))
    # IAM exposes no condition to poll for a role becoming assumable by a service; the
    # bounded retry in _crawl_to_ready waits out that propagation.
    return arn


def _create_crawler(glue, *, deadline: float, **kwargs: Any) -> None:
    """CreateCrawler, retrying every 2 s only Glue's refusal of a role it cannot assume yet
    (IAM propagation of the role this check just created) until the deadline."""
    from botocore.exceptions import ClientError

    while True:
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as err:
            error = err.response["Error"]
            if (error["Code"] != "InvalidInputException"
                    or "unable to assume provided role" not in error.get("Message", "")
                    or time.monotonic() >= deadline):
                raise
        time.sleep(2)


def _crawl_to_ready(glue, crawler: str, *, deadline: float) -> dict:
    """Start the crawler and poll to READY, retrying the IAM-propagation failure.

    Glue rejects StartCrawler with CrawlerRunningException if a crawl is already in flight and
    reports an unassumable role as a FAILED crawl once it has started, so the retry has to
    cover both: the state machine is Glue's, and no API reports that the role has propagated.
    """
    from botocore.exceptions import ClientError

    last: dict = {}
    while time.monotonic() < deadline:
        try:
            glue.start_crawler(Name=crawler)
        except ClientError as err:
            if err.response["Error"]["Code"] != "CrawlerRunningException":
                raise
        while time.monotonic() < deadline:
            state = glue.get_crawler(Name=crawler)["Crawler"]
            if state["State"] == "READY" and state.get("LastCrawl"):
                last = state["LastCrawl"]
                break
            time.sleep(2)
        if last.get("Status") != "FAILED":
            return last
        message = last.get("ErrorMessage") or ""
        if "assume role" not in message and "AssumeRole" not in message:
            return last
        time.sleep(2)
    return last


def _list_table_names(glue, database: str) -> list:
    names = []
    for page in glue.get_paginator("get_tables").paginate(DatabaseName=database):
        names.extend(t["Name"] for t in page.get("TableList", []))
    return sorted(names)


def _list_partitions(glue, database: str, table: str) -> list:
    parts = []
    for page in glue.get_paginator("get_partitions").paginate(DatabaseName=database,
                                                              TableName=table):
        parts.extend(page.get("Partitions", []))
    return parts


def _retry_delete(fn: Callable[[], Any], label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions:
    a throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "NoSuchBucket",
            "ResourceNotFoundException", "404")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "CrawlerRunningException", "DeleteConflict", "InvalidInputException",
                 "RequestLimitExceeded")
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
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    _retry_delete(lambda: s3.delete_bucket(Bucket=bucket), f"s3 bucket {bucket}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
