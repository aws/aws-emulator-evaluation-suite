"""query-execution-missing-table-fails-with-athena-error."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-execution-missing-table-fails-with-athena-error"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "dp:api", "plane:data")
def run(ctx) -> None:
    """SELECT against a table that does not exist in the Glue catalog is accepted at
    StartQueryExecution time (syntactically valid) but fails at RUNNING with a table-not-found
    AthenaError, distinct from a syntax failure."""
    bucket = _create_results_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/results/"

    # An account is not guaranteed to have a Glue "default" database (without one, SELECT
    # against default.<anything> fails SCHEMA_NOT_FOUND before the table lookup happens).
    # Create our own database so the missing table is the only thing under test.
    db = ctx.unique_name("sim2real_athena_db_").replace("-", "_")
    create_qid = athena.start_query_execution(
        QueryString=f"CREATE DATABASE {db}", ResultConfiguration={"OutputLocation": out}
    )["QueryExecutionId"]
    created = _poll_query_execution(ctx, create_qid)
    assert created["Status"]["State"] == "SUCCEEDED", created["Status"]
    ctx.on_cleanup(
        lambda: _poll_query_execution(
            ctx,
            athena.start_query_execution(
                QueryString=f"DROP DATABASE {db}", ResultConfiguration={"OutputLocation": out}
            )["QueryExecutionId"],
        )
    )

    # positive control: prove this database/workgroup/output-location can execute a query at
    # all, so the FAILED below is attributable to the missing table, not a broken setup.
    control_qid = athena.start_query_execution(
        QueryString="SELECT 1",
        QueryExecutionContext={"Database": db},
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    control = _poll_query_execution(ctx, control_qid)
    assert control["Status"]["State"] == "SUCCEEDED", control["Status"]

    missing_table = ctx.unique_name("sim2real_athena_missing_").replace("-", "_")
    qid = athena.start_query_execution(
        QueryString=f"SELECT * FROM {db}.{missing_table} LIMIT 1",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]

    execution = _poll_query_execution(ctx, qid)
    assert execution["Status"]["State"] == "FAILED", execution["Status"]
    athena_error = execution["Status"].get("AthenaError")
    assert athena_error is not None, execution["Status"]
    message = athena_error.get("ErrorMessage", "")
    assert missing_table in message or "TABLE_NOT_FOUND" in message.upper() or "not found" in message.lower(), message


def _create_results_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    def _cleanup():
        token = None
        while True:
            kw = {"Bucket": bucket}
            if token:
                kw["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kw)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            if resp.get("IsTruncated"):
                token = resp.get("NextContinuationToken")
            else:
                break
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _poll_query_execution(ctx, qid, timeout_s=120.0, interval_s=1.5):
    athena = ctx.client("athena")
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        last = resp
        if resp["Status"]["State"] in terminal:
            return resp
        time.sleep(interval_s)
    state = last["Status"]["State"] if last else "?"
    raise AssertionError(f"query {qid} stuck in {state} after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
