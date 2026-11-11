"""query-result-reuse-cache-hit-on-rerun."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-result-reuse-cache-hit-on-rerun"
GROUP = "query-execution"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Re-running the identical query string in the same workgroup with ResultReuseConfiguration
    enabled marks the second execution's Statistics.ResultReuseInformation.ReusedPreviousResult
    True, while the first (fresh) execution reports it False."""
    bucket = _create_results_bucket(ctx)
    athena = ctx.client("athena")
    marker = ctx.unique_name("marker-")
    query = f"SELECT '{marker}' AS marker, count(*) AS c FROM (VALUES (1), (2), (3)) AS t(x)"
    reuse_cfg = {"ResultReuseByAgeConfiguration": {"Enabled": True, "MaxAgeInMinutes": 60}}
    out_loc = {"OutputLocation": f"s3://{bucket}/results/"}

    qid1 = athena.start_query_execution(
        QueryString=query, ResultConfiguration=out_loc, ResultReuseConfiguration=reuse_cfg
    )["QueryExecutionId"]
    exec1 = _poll_query_execution(ctx, qid1)
    assert exec1["Status"]["State"] == "SUCCEEDED", exec1["Status"]
    reused1 = exec1.get("Statistics", {}).get("ResultReuseInformation", {}).get("ReusedPreviousResult")
    assert reused1 is not True, f"first execution unexpectedly reported reuse: {reused1}"

    qid2 = athena.start_query_execution(
        QueryString=query, ResultConfiguration=out_loc, ResultReuseConfiguration=reuse_cfg
    )["QueryExecutionId"]
    assert qid2 != qid1
    exec2 = _poll_query_execution(ctx, qid2)
    assert exec2["Status"]["State"] == "SUCCEEDED", exec2["Status"]
    reused2 = exec2.get("Statistics", {}).get("ResultReuseInformation", {}).get("ReusedPreviousResult")
    assert reused2 is True, f"second identical execution did not reuse cached result: {reused2}"

    results = athena.get_query_results(QueryExecutionId=qid2)
    rows = results["ResultSet"]["Rows"]
    values = [c.get("VarCharValue") for c in rows[1]["Data"]]
    assert values == [marker, "3"], values


def _create_results_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "query-result-reuse-cache-hit-on-rerun"},
        {"Key": "sim2real:managed", "Value": "true"},
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
