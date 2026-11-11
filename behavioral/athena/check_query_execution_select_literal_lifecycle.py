"""query-execution-select-literal-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-execution-select-literal-lifecycle"
GROUP = "query-execution"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQueryExecution on a trivial SELECT reaches SUCCEEDED and GetQueryResults returns
    the exact header row and data row Athena computed."""
    bucket = _create_results_bucket(ctx)
    athena = ctx.client("athena")
    qid = athena.start_query_execution(
        QueryString="SELECT 1 AS one, 'hello' AS greeting",
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]
    # No cleanup registered: queries are not deletable; nothing to clean beyond the bucket

    execution = _poll_query_execution(ctx, qid)
    assert execution["Status"]["State"] == "SUCCEEDED", execution["Status"]

    results = athena.get_query_results(QueryExecutionId=qid)
    rows = results["ResultSet"]["Rows"]
    assert len(rows) == 2, f"expected header+data row, got {rows}"
    header = [c.get("VarCharValue") for c in rows[0]["Data"]]
    data = [c.get("VarCharValue") for c in rows[1]["Data"]]
    assert header == ["one", "greeting"], header
    assert data == ["1", "hello"], data

    columns = results["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
    assert columns[0]["Name"] == "one" and columns[0]["Type"] == "integer", columns[0]
    assert columns[1]["Name"] == "greeting" and columns[1]["Type"] == "varchar", columns[1]


def _create_results_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]}
    )

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
