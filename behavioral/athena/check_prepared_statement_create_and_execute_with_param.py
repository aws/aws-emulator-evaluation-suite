"""prepared-statement-create-and-execute-with-param."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "prepared-statement-create-and-execute-with-param"
GROUP = "prepared-statement"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A prepared statement with '?' placeholders, invoked as EXECUTE ... USING <args> through
    StartQueryExecution, substitutes the positional parameters and returns the exact bound
    values in the result set."""
    bucket = _create_results_bucket(ctx)
    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(
        Name=wg_name,
        Tags=[{"Key": "sim2real", "Value": "prepared-statement-create-and-execute-with-param"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    stmt_name = ctx.unique_name("sim2real_stmt_").replace("-", "_")
    athena.create_prepared_statement(
        StatementName=stmt_name,
        WorkGroup=wg_name,
        QueryStatement="SELECT ? AS n, ? AS s",
    )
    ctx.on_cleanup(lambda: athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg_name))

    qid = athena.start_query_execution(
        QueryString=f"EXECUTE {stmt_name} USING 42, 'hi'",
        WorkGroup=wg_name,
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]

    execution = _poll_query_execution(ctx, qid)
    assert execution["Status"]["State"] == "SUCCEEDED", execution["Status"]

    results = athena.get_query_results(QueryExecutionId=qid)
    rows = results["ResultSet"]["Rows"]
    header = [c.get("VarCharValue") for c in rows[0]["Data"]]
    data = [c.get("VarCharValue") for c in rows[1]["Data"]]
    assert header == ["n", "s"], header
    assert data == ["42", "hi"], data


def _create_results_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-").lower().replace("_", "-")
    kwargs = {}
    # us-east-1 rejects CreateBucketConfiguration/LocationConstraint outright; every other
    # region requires it. Not a region pin on the check itself.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "prepared-statement-create-and-execute-with-param"},
    ]})

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
