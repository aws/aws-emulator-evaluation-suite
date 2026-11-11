"""athena-query-execution-success-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "athena-query-execution-success-lifecycle"
GROUP = "state"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQueryExecution QUEUED->...->SUCCEEDED and GetQueryResults returns the exact rows."""
    bucket = _create_result_bucket(ctx)
    athena = ctx.client("athena")

    qid = athena.start_query_execution(
        QueryString="SELECT 1 AS col",
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]

    qe = _wait_query_terminal(ctx, qid, timeout_s=90)
    assert qe["Status"]["State"] == "SUCCEEDED", qe["Status"]
    # A literal SELECT with no FROM scans no data, so AWS reports DataScannedInBytes == 0.
    assert qe["Statistics"]["DataScannedInBytes"] == 0, qe["Statistics"]
    assert qe["Query"] == "SELECT 1 AS col", qe["Query"]
    assert qe["StatementType"] == "DML", qe["StatementType"]

    results = athena.get_query_results(QueryExecutionId=qid)
    col_info = results["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
    assert len(col_info) == 1, col_info
    assert col_info[0]["Name"] == "col", col_info[0]
    assert col_info[0]["Type"] == "integer", col_info[0]

    rows = results["ResultSet"]["Rows"]
    assert len(rows) == 2, rows  # header row + one data row
    assert rows[0]["Data"][0]["VarCharValue"] == "col", rows[0]
    assert rows[1]["Data"][0]["VarCharValue"] == "1", rows[1]


def _create_result_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-res-")
    # S3 rejects an explicit LocationConstraint for us-east-1 (its own implicit default).
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _wait_query_terminal(ctx, query_execution_id: str, timeout_s: float = 90.0) -> dict:
    athena = ctx.client("athena")
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = athena.get_query_execution(QueryExecutionId=query_execution_id)["QueryExecution"]
        if last["Status"]["State"] in terminal:
            return last
        time.sleep(2.0)
    raise AssertionError(f"query {query_execution_id} did not reach a terminal state: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
