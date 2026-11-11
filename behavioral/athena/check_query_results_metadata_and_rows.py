"""query-results-metadata-and-rows."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-results-metadata-and-rows"
GROUP = "data-plane-depth"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetQueryResults returns byte-accurate values and correctly typed column metadata
    for a multi-type projection."""
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/out/"

    qid = athena.start_query_execution(
        QueryString="SELECT CAST(42 AS INTEGER) AS num, 'hello' AS txt, true AS flag",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    execution = _wait_for_query(ctx, qid)
    assert execution["Status"]["State"] == "SUCCEEDED", execution["Status"]

    results = athena.get_query_results(QueryExecutionId=qid)
    cols = results["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
    by_name = {c["Name"]: c["Type"].lower() for c in cols}
    assert by_name["num"] == "integer", by_name
    assert by_name["txt"] == "varchar", by_name
    assert by_name["flag"] == "boolean", by_name

    data_row = results["ResultSet"]["Rows"][1]["Data"]
    assert data_row[0]["VarCharValue"] == "42", data_row[0]
    assert data_row[1]["VarCharValue"] == "hello", data_row[1]
    assert data_row[2]["VarCharValue"] == "true", data_row[2]


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # us-east-1 rejects a CreateBucketConfiguration/LocationConstraint on create_bucket.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
