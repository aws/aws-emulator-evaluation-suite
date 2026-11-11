"""query-results-pagination-next-token-exactness."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "query-results-pagination-next-token-exactness"
GROUP = 'query-execution'
SERVICES = ['athena']


_CSV_ROWS = (
    "1,alpha,10.5,true\n"
    "2,bravo,20.25,false\n"
    "3,charlie,30.75,true\n"
    "4,delta,40.0,false\n"
    "5,echo,50.5,true\n"
    "6,foxtrot,60.25,false\n"
)


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object before DeleteBucket.

    Athena writes its own result artifacts (`<qid>.csv`, `<qid>.csv.metadata`,
    `<qid>.txt` for DDL) into the output location, so a bucket that only ever
    received our uploads is still non-empty at teardown. DeleteBucket on a
    non-empty bucket fails, and a failed DeleteBucket is the single most likely
    cost leak in this service — hence the paginated delete_objects sweep.
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
    # registered BEFORE the name is used anywhere else
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
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
    """Poll GetQueryExecution to a REQUIRED terminal state with a bounded deadline.

    300s (not the 30-90s the existing athena checks use): a query over a real
    EXTERNAL TABLE additionally pays Glue metadata resolution, split planning and
    S3 listing, and the account's query queue is shared. A bare time.sleep would
    not be an assertion; timing out here is a hard failure, not a pass.
    """
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


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


def _external_table(ctx, athena, out):
    """Stand up the cheapest real Athena data source: one tiny CSV object in S3 registered
    as a typed EXTERNAL TABLE. Returns (database, table, data_bytes).

    Cleanups are registered at creation time and the runner runs them LIFO, so the
    registration order (results bucket -> data bucket -> DROP DATABASE CASCADE) tears
    down as DROP DATABASE -> data bucket -> results bucket. DROP DATABASE is itself an
    Athena query, so the results bucket must outlive it — which LIFO guarantees.
    """
    s3 = ctx.client("s3")
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")
    body = _CSV_ROWS.encode()
    s3.put_object(Bucket=data_bucket, Key="data/rows.csv", Body=body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-tbl-").replace("-", "_")
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena,
        out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` "
        "(`id` int, `name` string, `amount` double, `active` boolean) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/data/'",
    )
    return database, table, len(body)


def _dml_name(database, table):
    """Fully-qualified table name for a DML (SELECT/EXECUTE) statement.

    Athena parses DDL with the Hive parser, which quotes identifiers with BACKTICKS, but
    parses DML with the Trino parser, which quotes them with DOUBLE QUOTES. A backtick
    inside a SELECT makes the statement unclassifiable and StartQueryExecution refuses it
    SYNCHRONOUSLY with `InvalidRequestException: Queries of this type are not supported`
    (on real AWS the identical SELECT is
    accepted unquoted or double-quoted, and refused backtick-quoted, while
    a backtick-quoted CREATE EXTERNAL TABLE and SHOW TABLES both succeed).
    So the DDL below keeps its backticks and every DML statement goes through here.
    """
    return f'"{database}"."{table}"'





@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetQueryResults pagination: the header row appears on page 1 only, NextToken is
    present on every page but the last, and concatenating the pages reproduces the
    ORDER BY sequence exactly — no drops, no duplicates, no reshuffle."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    database, table, _ = _external_table(ctx, athena, out)

    qid = _start_query(
        athena, out, f"SELECT id, name FROM {_dml_name(database, table)} ORDER BY id", database=database
    )
    state = _wait_terminal(athena, qid)
    assert state == "SUCCEEDED", f"setup query {qid} must succeed before paging its results, got {state}"

    max_results = 2
    pages = []
    token = None
    # bounded: 7 rows at <=2 per page can never exceed 8 requests
    for _ in range(8):
        kwargs = {"QueryExecutionId": qid, "MaxResults": max_results}
        if token:
            kwargs["NextToken"] = token
        page = athena.get_query_results(**kwargs)
        pages.append(page)
        token = page.get("NextToken")
        if not token:
            break
    assert token is None, (
        "GetQueryResults still returned a NextToken after 8 pages of a 6-row result set — "
        "pagination does not terminate"
    )

    assert len(pages) >= 4, (
        f"1 header + 6 data rows at MaxResults={max_results} must span at least 4 pages, "
        f"got {len(pages)}"
    )
    for i, page in enumerate(pages):
        rows = page["ResultSet"]["Rows"]
        assert len(rows) <= max_results, (
            f"page {i} returned {len(rows)} rows, more than MaxResults={max_results}"
        )
        assert ("NextToken" in page) == (i < len(pages) - 1), (
            f"page {i} of {len(pages)}: NextToken must be present on every page except the "
            f"last, got NextToken={'present' if 'NextToken' in page else 'absent'}"
        )
        assert page["ResultSet"]["ResultSetMetadata"]["ColumnInfo"], (
            f"page {i} dropped ResultSetMetadata.ColumnInfo — every page must carry it"
        )

    first_page_rows = [
        [d.get("VarCharValue") for d in r["Data"]] for r in pages[0]["ResultSet"]["Rows"]
    ]
    assert first_page_rows[0] == ["id", "name"], (
        f"page 1 row 0 must be the header, got {first_page_rows[0]}"
    )

    collected = list(first_page_rows[1:])
    for i, page in enumerate(pages[1:], start=1):
        rows = [[d.get("VarCharValue") for d in r["Data"]] for r in page["ResultSet"]["Rows"]]
        assert ["id", "name"] not in rows, (
            f"page {i} repeated the header row — the header belongs to page 1 only: {rows}"
        )
        collected.extend(rows)

    expected = [
        ["1", "alpha"], ["2", "bravo"], ["3", "charlie"],
        ["4", "delta"], ["5", "echo"], ["6", "foxtrot"],
    ]
    assert collected == expected, (
        f"the concatenated pages must reproduce the ORDER BY id sequence exactly; "
        f"got {collected}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
