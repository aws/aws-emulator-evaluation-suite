"""query-execution-missing-table-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-execution-missing-table-fails"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query on a nonexistent table ends FAILED with a USER-category AthenaError, never SUCCEEDED,
    while a literal SELECT on the same workgroup succeeds."""
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/out/"
    db = ctx.unique_name("sim2real_athena_db_").replace("-", "_")

    qid1 = athena.start_query_execution(
        QueryString=f"CREATE DATABASE {db}",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    created = _wait_for_query(ctx, qid1)
    assert created["Status"]["State"] == "SUCCEEDED", created["Status"]
    ctx.on_cleanup(
        lambda: _wait_for_query(
            ctx,
            athena.start_query_execution(
                QueryString=f"DROP DATABASE {db}", ResultConfiguration={"OutputLocation": out}
            )["QueryExecutionId"],
        )
    )

    qid_control = athena.start_query_execution(
        QueryString="SELECT 1",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    control = _wait_for_query(ctx, qid_control)
    assert control["Status"]["State"] == "SUCCEEDED", (
        f"positive control 'SELECT 1' must succeed, got {control['Status']}"
    )

    missing_table = ctx.unique_name("no_such_tbl_").replace("-", "_")
    qid2 = athena.start_query_execution(
        QueryString=f"SELECT * FROM {db}.{missing_table}",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    failed = _wait_for_query(ctx, qid2)
    assert failed["Status"]["State"] == "FAILED", failed["Status"]
    err = failed["Status"]["AthenaError"]
    assert err["ErrorCategory"] == 2, err  # 2 = User error
    reason = failed["Status"]["StateChangeReason"]
    assert missing_table.upper() in reason.upper() or "TABLE" in reason.upper(), (
        f"StateChangeReason must name the missing table {missing_table!r} or say TABLE, got {reason!r}"
    )


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "query-execution-missing-table-fails"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

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
