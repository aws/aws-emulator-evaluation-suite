"""athena-query-results-written-to-s3-output-location-positive."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "athena-query-results-written-to-s3-output-location-positive"
GROUP = "result-delivery"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A successful Athena query execution writes its CSV result object to the
    configured S3 OutputLocation, and the object content matches the query result."""
    s3 = ctx.client("s3")
    athena = ctx.client("athena")

    bucket = _create_bucket(ctx, "out")
    prefix = "results/"
    output_location = f"s3://{bucket}/{prefix}"

    qid, state, exec_resp = _run_query(
        ctx,
        query="SELECT 'sim2real-marker' AS greeting, 7 AS num",
        output_location=output_location,
    )
    assert state == "SUCCEEDED", f"query did not succeed: {exec_resp['Status']}"

    result_key = f"{prefix}{qid}.csv"
    head = s3.head_object(Bucket=bucket, Key=result_key)
    assert head["ContentLength"] > 0, f"expected a non-empty result object, got ContentLength={head['ContentLength']}"

    body = s3.get_object(Bucket=bucket, Key=result_key)["Body"].read().decode("utf-8")
    assert "sim2real-marker" in body, f"expected 'sim2real-marker' in result body, got: {body!r}"
    assert "greeting" in body.splitlines()[0], f"expected header row to contain 'greeting', got: {body.splitlines()[0]!r}"

    # Cross-check the S3 object content against the GetQueryResults API for the
    # same execution id -- both must reflect the same underlying result set.
    api_rows = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
    assert len(api_rows) == 2, f"expected header row + 1 data row, got {len(api_rows)} rows: {api_rows}"  # header row + 1 data row
    data_row = api_rows[1]["Data"]
    assert data_row[0]["VarCharValue"] == "sim2real-marker", f"expected 'sim2real-marker', got {data_row[0]!r}"
    assert data_row[1]["VarCharValue"] == "7", f"expected '7', got {data_row[1]!r}"


def _create_bucket(ctx, kind: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-athena-{kind}-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _run_query(
    ctx,
    query: str,
    output_location: str | None = None,
    database: str | None = None,
    workgroup: str | None = None,
    timeout_s: float = 120.0,
):
    athena = ctx.client("athena")
    kwargs: dict = {"QueryString": query}
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    if output_location:
        kwargs["ResultConfiguration"] = {"OutputLocation": output_location}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    resp = athena.start_query_execution(**kwargs)
    qid = resp["QueryExecutionId"]
    deadline = time.monotonic() + timeout_s
    exec_resp = None
    state = None
    while time.monotonic() < deadline:
        exec_resp = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = exec_resp["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return qid, state, exec_resp
        time.sleep(2)
    raise AssertionError(f"query {qid} did not finish in {timeout_s}s, last state {state}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
