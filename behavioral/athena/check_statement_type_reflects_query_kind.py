"""statement-type-reflects-query-kind."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "statement-type-reflects-query-kind"
GROUP = "data-plane-depth"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetQueryExecution.StatementType classifies CREATE DATABASE as DDL, a plain
    SELECT as DML, and SHOW DATABASES as UTILITY."""
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/out/"
    db = ctx.unique_name("sim2real_athena_stmtdb_").replace("-", "_")

    qid_ddl = athena.start_query_execution(
        QueryString=f"CREATE DATABASE {db} LOCATION 's3://{bucket}/db/'",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    ddl_exec = _wait_for_query(ctx, qid_ddl)
    assert ddl_exec["Status"]["State"] == "SUCCEEDED", ddl_exec["Status"]
    assert ddl_exec["StatementType"] == "DDL", ddl_exec["StatementType"]

    ctx.on_cleanup(
        lambda: _wait_for_query(
            ctx,
            athena.start_query_execution(
                QueryString=f"DROP DATABASE {db}",
                ResultConfiguration={"OutputLocation": out},
            )["QueryExecutionId"],
        )
    )

    qid_dml = athena.start_query_execution(
        QueryString="SELECT 1", ResultConfiguration={"OutputLocation": out}
    )["QueryExecutionId"]
    dml_exec = _wait_for_query(ctx, qid_dml)
    assert dml_exec["Status"]["State"] == "SUCCEEDED", dml_exec["Status"]
    assert dml_exec["StatementType"] == "DML", dml_exec["StatementType"]

    qid_util = athena.start_query_execution(
        QueryString="SHOW DATABASES", ResultConfiguration={"OutputLocation": out}
    )["QueryExecutionId"]
    util_exec = _wait_for_query(ctx, qid_util)
    assert util_exec["Status"]["State"] == "SUCCEEDED", util_exec["Status"]
    assert util_exec["StatementType"] == "UTILITY", util_exec["StatementType"]


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    # us-east-1 is region-pinned here only because CreateBucket rejects an explicit
    # LocationConstraint for that region (IllegalLocationConstraintException).
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
