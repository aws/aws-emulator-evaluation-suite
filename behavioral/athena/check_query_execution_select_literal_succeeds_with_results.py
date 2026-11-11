"""query-execution-select-literal-succeeds-with-results."""

from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "query-execution-select-literal-succeeds-with-results"
GROUP = "query-execution"
SERVICES = ["athena"]


def _empty_and_delete_bucket(s3, bucket):
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


def _output_location(ctx):
    """Create an Athena query-results bucket (region-correct) and return its s3:// prefix."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-results-")
    kwargs = {"Bucket": bucket}
    # us-east-1 rejects CreateBucketConfiguration entirely; every other region requires it.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "query-execution-select-literal-succeeds-with-results"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return f"s3://{bucket}/results/"


def _start_query(
    athena, out, query_string, workgroup=None, client_request_token=None, database=None
):
    kwargs = {
        "QueryString": query_string,
        "ResultConfiguration": {"OutputLocation": out},
    }
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if client_request_token:
        kwargs["ClientRequestToken"] = client_request_token
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


# Two DISTINCT failure markers that name what is missing when the SQL engine does not run:
#   TARGET_STATE_UNIMPLEMENTED — the query was ACCEPTED but never reached a terminal state
#   DATAPLANE_UNIMPLEMENTED    — it reached a terminal state that is not SUCCEEDED for `SELECT 1`,
#                                i.e. nothing actually executed the SQL
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _wait_terminal(athena, qid, timeout_s=30, interval_s=1):
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"][
            "Status"
        ]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"{STATE_MARKER}: query {qid} did not reach a terminal state within {timeout_s}s "
        f"(last={state})"
    )


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data"
)
def run(ctx) -> None:
    """A trivial SELECT drives QUEUED/RUNNING->SUCCEEDED and GetQueryResults returns real data."""
    athena = ctx.client("athena")
    out = _output_location(ctx)
    qid = _start_query(athena, out, "SELECT 1 AS col1, 'athena' AS col2")

    state = _wait_terminal(athena, qid, timeout_s=60)
    # `SELECT 1 AS col1, 'athena' AS col2` has no table, no permission and no syntax question: the
    # only way it does not SUCCEED is that nothing executed it.
    assert state == "SUCCEEDED", f"{DATAPLANE_MARKER}: expected SUCCEEDED, got {state}"

    exec_info = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
    assert exec_info["Query"] == "SELECT 1 AS col1, 'athena' AS col2", (
        f"expected the persisted query text to match verbatim, got {exec_info['Query']!r}"
    )
    assert exec_info["Status"]["State"] == "SUCCEEDED", (
        f"expected SUCCEEDED on independent re-read, got {exec_info['Status']['State']}"
    )

    results = athena.get_query_results(QueryExecutionId=qid)
    columns = results["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
    col_names = [c["Name"] for c in columns]
    assert col_names == ["col1", "col2"], f"unexpected column names: {col_names}"

    rows = results["ResultSet"]["Rows"]
    # Athena's row 0 is the header, row 1 is the data for this style of query.
    assert len(rows) >= 2, f"expected header + data row, got {rows}"
    data_values = [d.get("VarCharValue") for d in rows[-1]["Data"]]
    assert data_values == ["1", "athena"], f"unexpected result data: {data_values}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
