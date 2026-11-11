"""view-select-returns-underlying-rows-and-is-not-a-table."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "view-select-returns-underlying-rows-and-is-not-a-table"
GROUP = 'metadata'
SERVICES = ['athena']



def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object before DeleteBucket.

    Athena writes its own result artifacts (`<qid>.csv`, `<qid>.csv.metadata`, `<qid>.txt` for
    DDL) into the output location, so a bucket that only ever received our uploads is still
    non-empty at teardown. DeleteBucket on a non-empty bucket fails, and a failed DeleteBucket is
    the single most likely cost leak in this service — hence the paginated delete_objects sweep.
    """
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "view-select-returns-underlying-rows"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _output_location(ctx):
    return f"s3://{_make_bucket(ctx, 'sim2real-behav-athena-results-')}/results/"


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
    rows[1:]. Returned as a LIST, never a set — ORDER BY makes the order a server-side guarantee
    and an emulator that shuffles must fail."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers). CREATE VIEW and every SELECT through it are Trino DML, so they go
    through here; the CREATE EXTERNAL TABLE below keeps its backticks."""
    return f'"{database}"."{table}"'


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2", "cap:c3")
def run(ctx) -> None:
    """A view has no storage of its own: GetTableMetadata reports it as VIRTUAL_VIEW, its SELECT
    returns the projected, filtered rows of the underlying table, and adding a row to the
    underlying S3 data changes what the same view returns without the view being touched."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    out = _output_location(ctx)
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    # A per-run marker so the view's rows cannot be a hardcoded fixture.
    marker = ctx.unique_name("").replace("-", "")[:12]
    s3.put_object(Bucket=data_bucket, Key="src/rows.csv",
                  Body=f"1,alpha-{marker}\n2,bravo-{marker}\n3,charlie-{marker}\n".encode())

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-tbl-").replace("-", "_")
    view = ctx.unique_name("sim2real-behav-vw-").replace("-", "_")
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` (`id` int, `name` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'",
    )

    # --- create the view; the DROP DATABASE CASCADE above already covers it, so no extra
    #     registration is needed and none is invented ---
    _run_sql(
        athena, out,
        f"CREATE VIEW {_dml_name(database, view)} AS "
        f"SELECT name FROM {_dml_name(database, table)} WHERE id > 1",
        database=database,
    )

    # --- it is a VIEW in the metastore, not a table ---
    meta = athena.get_table_metadata(
        CatalogName="AwsDataCatalog", DatabaseName=database, TableName=view)["TableMetadata"]
    assert meta["TableType"] == "VIRTUAL_VIEW", (
        f"a view created with CREATE VIEW must be reported as VIRTUAL_VIEW, got "
        f"{meta.get('TableType')!r} for {view!r}")
    tbl_meta = athena.get_table_metadata(
        CatalogName="AwsDataCatalog", DatabaseName=database, TableName=table)["TableMetadata"]
    assert tbl_meta["TableType"] == "EXTERNAL_TABLE", (
        f"the control table must still be an EXTERNAL_TABLE, so TableType is really discriminating "
        f"and not a constant; got {tbl_meta.get('TableType')!r}")

    # --- leg 1: the view projects and filters ---
    q1 = _run_sql(athena, out,
                  f"SELECT name FROM {_dml_name(database, view)} ORDER BY name",
                  database=database)
    rows1 = _data_rows(athena.get_query_results(QueryExecutionId=q1))
    assert rows1 == [[f"bravo-{marker}"], [f"charlie-{marker}"]], (
        f"the view must return only the two rows with id > 1, projected to `name`, in ORDER BY "
        f"order; marker was {marker!r} and the view returned {rows1!r}")

    # --- leg 2: change the UNDERLYING data; the same view query must see it ---
    s3.put_object(Bucket=data_bucket, Key="src/rows2.csv", Body=f"4,delta-{marker}\n".encode())
    q2 = _run_sql(athena, out,
                  f"SELECT name FROM {_dml_name(database, view)} ORDER BY name",
                  database=database)
    rows2 = _data_rows(athena.get_query_results(QueryExecutionId=q2))
    assert rows2 == [[f"bravo-{marker}"], [f"charlie-{marker}"], [f"delta-{marker}"]], (
        f"the identical view query must re-read the underlying S3 location and pick up the new "
        f"row; it returned {rows2!r} (before the write it returned {rows1!r})")

    # --- and the definition's WHERE clause is still being applied to the new data ---
    assert f"alpha-{marker}" not in [r[0] for r in rows2], (
        f"the view's WHERE id > 1 must still exclude the id=1 row after the underlying data "
        f"changed; got {rows2!r}")

    # --- the view really has no storage: the underlying table's location holds only the CSVs ---
    view_scanned = athena.get_query_execution(QueryExecutionId=q2)["QueryExecution"][
        "Statistics"]["DataScannedInBytes"]
    assert view_scanned > 0, (
        f"a view query must scan the underlying objects, got DataScannedInBytes="
        f"{view_scanned!r} — a fabricated ResultSet scans nothing")
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=data_bucket, Prefix="src/"):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    assert sorted(keys) == ["src/rows.csv", "src/rows2.csv"], (
        f"creating and querying a view must write nothing into the source location — a view has "
        f"no storage; the prefix now holds {sorted(keys)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
