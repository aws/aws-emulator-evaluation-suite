"""query-execution-values-multirow-results-exact."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-execution-values-multirow-results-exact"
GROUP = "query-execution"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A multi-row, multi-column SELECT ... ORDER BY returns rows in the exact order and
    values submitted, byte-identical as strings in GetQueryResults."""
    bucket = _create_results_bucket(ctx)
    athena = ctx.client("athena")
    qid = athena.start_query_execution(
        QueryString=(
            "SELECT * FROM (VALUES (1, 'alpha'), (2, 'beta'), (3, 'gamma')) AS t(id, name) "
            "ORDER BY id"
        ),
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]

    execution = _poll_query_execution(ctx, qid)
    assert execution["Status"]["State"] == "SUCCEEDED", execution["Status"]

    results = athena.get_query_results(QueryExecutionId=qid)
    rows = results["ResultSet"]["Rows"]
    assert len(rows) == 4, f"expected header + 3 data rows, got {len(rows)}"
    values = [[c.get("VarCharValue") for c in r["Data"]] for r in rows]
    assert values[0] == ["id", "name"], values[0]
    assert values[1:] == [["1", "alpha"], ["2", "beta"], ["3", "gamma"]], values[1:]


def _create_results_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-").lower().replace("_", "-")
    kwargs = {}
    # S3 rejects an explicit LocationConstraint of us-east-1; it is the only region that
    # must omit CreateBucketConfiguration entirely (this is an S3 quirk, not a region pin).
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK},
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
