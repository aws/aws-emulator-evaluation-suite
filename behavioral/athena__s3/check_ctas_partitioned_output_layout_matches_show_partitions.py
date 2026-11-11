"""ctas-partitioned-output-layout-matches-show-partitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ctas-partitioned-output-layout-matches-show-partitions"
GROUP = 'query-execution'
SERVICES = ['athena', 's3']



_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags():
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv():
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind):
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_bucket(s3, bucket):
    """Empty a bucket (objects, versions, delete markers) then delete it: Athena results and CTAS
    output land in it too, and DeleteBucket fails on a non-empty bucket."""
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


def _all_rows(results):
    """Every row, header included. SHOW PARTITIONS emits NO header row, so slicing rows[1:] would
    silently drop a partition."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows]


def _keys_under(s3, bucket, prefix):
    """PAGINATED listing of a prefix: a CTAS writes one object per partition per writer."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers). CTAS and SELECT are Trino DML; CREATE EXTERNAL TABLE, SHOW
    PARTITIONS and MSCK REPAIR are Hive DDL and keep their backticks."""
    return f'"{database}"."{table}"'


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c3",
)
def run(ctx) -> None:
    """A partitioned CTAS writes Parquet objects under exactly one Hive-style `dt=<value>/` prefix
    per partition value, SHOW PARTITIONS lists exactly those prefixes, every row round-trips, and a
    partition-key predicate scans only that partition."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, "athena-ctas")
    out = f"s3://{bucket}/results/"

    # A per-run marker so the CTAS-materialised values cannot be a hardcoded fixture.
    marker = ctx.unique_name("").replace("-", "")[:12]
    src_csv = (
        f"1,alpha-{marker},2024-01-01\n"
        f"2,bravo-{marker},2024-01-02\n"
        f"3,charlie-{marker},2024-01-02\n"
    ).encode()
    s3.put_object(Bucket=bucket, Key="src/rows.csv", Body=src_csv,
                  Tagging="sim2real%3Amanaged=true")

    database = _xname(ctx, "db").replace("-", "_")
    src = _xname(ctx, "src").replace("-", "_")
    tgt = _xname(ctx, "tgt").replace("-", "_")
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{src}` "
        "(`id` int, `name` string, `dt` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{bucket}/src/'",
    )
    src_count = _data_rows(athena.get_query_results(QueryExecutionId=_run_sql(
        athena, out, f"SELECT count(*) FROM {_dml_name(database, src)}", database=database)))
    assert src_count == [["3"]], f"the source table must hold the three seeded rows, got {src_count!r}"

    # --- act: a partitioned CTAS into a prefix that is unique per run ---
    tgt_prefix = f"ctas/{tgt}/"
    _run_sql(
        athena, out,
        f"CREATE TABLE {_dml_name(database, tgt)} WITH (format = 'PARQUET', "
        f"partitioned_by = ARRAY['dt'], external_location = 's3://{bucket}/{tgt_prefix}') AS "
        f"SELECT id, name, dt FROM {_dml_name(database, src)}",
        database=database,
    )

    # --- the cross-boundary observable: the physical layout the engine produced in S3 ---
    keys = _keys_under(s3, bucket, tgt_prefix)
    assert keys, (
        f"CTAS must write objects under s3://{bucket}/{tgt_prefix} — the statement SUCCEEDED but "
        f"the prefix is empty")
    prefixes = sorted({k[len(tgt_prefix):].split("/")[0] for k in keys})
    assert prefixes == ["dt=2024-01-01", "dt=2024-01-02"], (
        f"CTAS with partitioned_by must lay its output out under one Hive-style prefix per "
        f"distinct partition value and nothing else; the prefixes under {tgt_prefix!r} are "
        f"{prefixes!r} (full keys {keys!r})")
    # CTAS object names carry no `.parquet` suffix, so the format is checked by its magic bytes.
    for key in keys:
        head = s3.get_object(Bucket=bucket, Key=key, Range="bytes=0-3")["Body"].read()
        assert head == b"PAR1", (
            f"the CTAS declared format='PARQUET', so the object it wrote at {key!r} must begin "
            f"with the PAR1 magic; its first four bytes are {head!r}")

    # --- and the metastore agrees with the bucket, exactly ---
    # SHOW PARTITIONS returns its rows in no fixed order, hence the sort.
    qsp = _run_sql(athena, out, f"SHOW PARTITIONS `{database}`.`{tgt}`")
    listed = sorted(r[0] for r in _all_rows(athena.get_query_results(QueryExecutionId=qsp)))
    assert listed == prefixes, (
        f"SHOW PARTITIONS must list exactly the partitions that exist in S3; the metastore says "
        f"{listed!r} and the bucket holds {prefixes!r}")

    # --- no rows were lost, and the values really round-tripped through Parquet ---
    tgt_rows = _data_rows(athena.get_query_results(QueryExecutionId=_run_sql(
        athena, out, f"SELECT id, name, dt FROM {_dml_name(database, tgt)} ORDER BY id",
        database=database)))
    assert tgt_rows == [["1", f"alpha-{marker}", "2024-01-01"],
                        ["2", f"bravo-{marker}", "2024-01-02"],
                        ["3", f"charlie-{marker}", "2024-01-02"]], (
        f"the CTAS target must return every source row with this run's marker {marker!r} intact, "
        f"in ORDER BY id order; got {tgt_rows!r}")

    # --- partition pruning works on the CTAS output, so the prefixes are really partitions ---
    pruned_qid = _run_sql(
        athena, out,
        f"SELECT name FROM {_dml_name(database, tgt)} WHERE dt = '2024-01-01'",
        database=database)
    pruned_rows = _data_rows(athena.get_query_results(QueryExecutionId=pruned_qid))
    assert pruned_rows == [[f"alpha-{marker}"]], (
        f"a predicate on the CTAS partition key must select only that prefix's row, got "
        f"{pruned_rows!r}")
    single_partition_bytes = athena.get_query_execution(QueryExecutionId=pruned_qid)[
        "QueryExecution"]["Statistics"]["DataScannedInBytes"]
    p1_keys = [k for k in keys if k.startswith(f"{tgt_prefix}dt=2024-01-01/")]
    p1_size = sum(s3.head_object(Bucket=bucket, Key=k)["ContentLength"] for k in p1_keys)
    assert 0 < single_partition_bytes <= p1_size, (
        f"the pruned read must scan bytes from ONLY the dt=2024-01-01 objects, whose total size is "
        f"{p1_size}; DataScannedInBytes was {single_partition_bytes!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
