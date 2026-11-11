"""execute-prepared-statement-with-parameter."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "execute-prepared-statement-with-parameter"
GROUP = "data-plane-depth"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A prepared statement with a '?' placeholder, run via EXECUTE ... USING <value>,
    substitutes the value into the query result exactly."""
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/out/"
    stmt_name = ctx.unique_name("sim2real_athena_execstmt_").replace("-", "_")

    athena.create_prepared_statement(
        StatementName=stmt_name, WorkGroup="primary", QueryStatement="SELECT ? AS val"
    )
    ctx.on_cleanup(
        lambda: athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup="primary")
    )

    qid = athena.start_query_execution(
        QueryString=f"EXECUTE {stmt_name} USING 777",
        WorkGroup="primary",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    execution = _wait_for_query(ctx, qid)
    assert execution["Status"]["State"] == "SUCCEEDED", execution["Status"]

    results = athena.get_query_results(QueryExecutionId=qid)
    bound = results["ResultSet"]["Rows"][1]["Data"][0]["VarCharValue"]
    assert bound == "777", f"EXECUTE ... USING 777 must bind the parameter as 777, got {bound!r}"


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        while objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
            resp = s3.list_objects_v2(Bucket=bucket)
            objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _wait_for_query(ctx, qid, timeout_s=180.0, interval_s=2.0):
    athena = ctx.client("athena")
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=qid)
        last = resp["QueryExecution"]
        if last["Status"]["State"] in terminal:
            return last
        time.sleep(interval_s)
    state = last["Status"]["State"] if last else None
    raise AssertionError(f"query {qid} did not reach terminal state within {timeout_s}s (last={state})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
