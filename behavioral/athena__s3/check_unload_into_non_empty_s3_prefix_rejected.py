"""unload-into-non-empty-s3-prefix-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unload-into-non-empty-s3-prefix-rejected"
GROUP = 'query-execution'
SERVICES = ['athena', 's3']


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"

#: AthenaError identity of a destination-collision refusal: type 1109 in category 2 (CLIENT).
_HIVE_PATH_ALREADY_EXISTS_TYPE = 1109
_CLIENT_ERROR_CATEGORY = 2


def _xsvc_resource_tags():
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv():
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind):
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_bucket(s3, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it.

    Athena writes result artifacts and UNLOAD output into the bucket, so it is never empty here.
    """
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, kind="bkt"):
    """Create a uniquely-named, region-correct bucket; register empty+delete teardown."""
    s3 = ctx.client("s3")
    name = _xname(ctx, kind)
    params = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(ctx.client("s3"), name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    return name


def _start_query(athena, out, query_string, workgroup=None, database=None, **extra):
    kwargs = {"QueryString": query_string, "ResultConfiguration": {"OutputLocation": out}}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    kwargs.update(extra)
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a REQUIRED terminal state with a bounded deadline."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


def _run_sql(athena, out, sql, database=None, workgroup=None, **extra):
    qid = _start_query(athena, out, sql, database=database, workgroup=workgroup, **extra)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state}, expected SUCCEEDED: {sql!r} -- "
            f"{status.get('StateChangeReason')}"
        )
    return qid


def _data_rows(results):
    """GetQueryResults rows for a SELECT: row 0 repeats the column names, so the data rows are
    rows[1:]."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _keys_under(s3, bucket, prefix):
    """Sorted, paginated listing of the keys under a prefix."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers). UNLOAD and SELECT are Trino DML."""
    return f'"{database}"."{table}"'


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c3",
)
def run(ctx) -> None:
    """UNLOAD into a non-empty S3 prefix fails with AthenaError 1109/category 2 HIVE_PATH_ALREADY_EXISTS
    and leaves the existing object untouched; the same UNLOAD into an empty prefix writes Parquet.
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, "athena-unload")
    out = f"s3://{bucket}/results/"

    # A per-run marker so neither the source rows nor the squatting object can be a fixture.
    marker = ctx.unique_name("").replace("-", "")[:12]
    s3.put_object(Bucket=bucket, Key="src/rows.csv",
                  Body=f"1,alpha-{marker}\n2,bravo-{marker}\n".encode())

    database = _xname(ctx, "db").replace("-", "_")
    src = _xname(ctx, "src").replace("-", "_")
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{src}` (`id` int, `name` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{bucket}/src/'",
    )
    unload_sql = f"SELECT id, name FROM {_dml_name(database, src)} ORDER BY id"

    # The one thing broken: the destination prefix already holds an object.
    taken_prefix = "occupied/"
    squatter_key = f"{taken_prefix}do-not-overwrite.txt"
    squatter_body = f"pre-existing-{marker}".encode()
    s3.put_object(Bucket=bucket, Key=squatter_key, Body=squatter_body)
    before = _keys_under(s3, bucket, taken_prefix)
    assert before == [squatter_key], (
        f"the destination prefix must start out holding exactly the squatting object, got {before!r}")

    # The refusal is asynchronous: a FAILED QueryExecution carrying AthenaError, not an API error.
    qid = _start_query(
        athena, out,
        f"UNLOAD ({unload_sql}) TO 's3://{bucket}/{taken_prefix}' WITH (format = 'PARQUET')",
        database=database)
    state = _wait_terminal(athena, qid)
    status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
    assert state == "FAILED", (
        f"UNLOAD into the non-empty prefix s3://{bucket}/{taken_prefix} must fail; it reached "
        f"{state!r} — an emulator that accepts it would silently overwrite customer data. "
        f"Status was {status!r}")
    reason = status.get("StateChangeReason") or ""
    assert reason.startswith("HIVE_PATH_ALREADY_EXISTS: Target directory already exists: "), (
        f"the failure must name the destination collision as its cause, got "
        f"StateChangeReason {reason!r}")
    assert f"s3://{bucket}/{taken_prefix}" in reason, (
        f"the reason must name the prefix that collided, got {reason!r}")
    err = status.get("AthenaError")
    assert err is not None, (
        f"a HIVE_PATH_ALREADY_EXISTS failure must carry AthenaError; Status was {status!r}")
    assert err["ErrorType"] == _HIVE_PATH_ALREADY_EXISTS_TYPE, (
        f"the refusal must be reported as ErrorType {_HIVE_PATH_ALREADY_EXISTS_TYPE}, got {err!r}")
    assert err["ErrorCategory"] == _CLIENT_ERROR_CATEGORY, (
        f"a destination the client chose badly is a CLIENT error (category "
        f"{_CLIENT_ERROR_CATEGORY}), got {err!r}")
    assert err["Retryable"] is False, (
        f"retrying will collide again, so the error must not be marked retryable, got {err!r}")

    after = _keys_under(s3, bucket, taken_prefix)
    assert after == [squatter_key], (
        f"the refused UNLOAD must write NOTHING into the prefix it was refused from; it now holds "
        f"{after!r} instead of just {[squatter_key]!r}")
    still = s3.get_object(Bucket=bucket, Key=squatter_key)["Body"].read()
    assert still == squatter_body, (
        f"the pre-existing object must be byte-identical after the refusal; it now reads "
        f"{still!r} instead of {squatter_body!r}")

    # Positive control: the same UNLOAD into a fresh prefix in the same bucket works.
    free_prefix = "vacant/"
    assert _keys_under(s3, bucket, free_prefix) == [], (
        "the control prefix must be empty before the control UNLOAD")
    control_qid = _run_sql(
        athena, out,
        f"UNLOAD ({unload_sql}) TO 's3://{bucket}/{free_prefix}' WITH (format = 'PARQUET')",
        database=database)
    control_keys = _keys_under(s3, bucket, free_prefix)
    assert control_keys, (
        f"the identical UNLOAD into an empty prefix must write objects, proving the refusal above "
        f"was the prefix collision and not a broken statement; s3://{bucket}/{free_prefix} is empty")
    for key in control_keys:
        head = s3.get_object(Bucket=bucket, Key=key, Range="bytes=0-3")["Body"].read()
        assert head == b"PAR1", (
            f"the control UNLOAD declared format='PARQUET', so {key!r} must begin with the PAR1 "
            f"magic; its first four bytes are {head!r}")
    manifest_key = f"results/{control_qid}-manifest.csv"
    manifest = s3.get_object(Bucket=bucket, Key=manifest_key)["Body"].read().decode()
    for key in control_keys:
        assert f"s3://{bucket}/{key}" in manifest, (
            f"the control UNLOAD's manifest at {manifest_key!r} must list every object it wrote; "
            f"{key!r} is missing from {manifest!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
