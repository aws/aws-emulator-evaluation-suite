"""list-query-executions-reflects-workgroup-scope."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-query-executions-reflects-workgroup-scope"
GROUP = "workgroup"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListQueryExecutions(WorkGroup=X) returns only query executions submitted to workgroup
    X; a query run in a distinct workgroup does not appear in another workgroup's listing."""
    bucket = _create_results_bucket(ctx)
    athena = ctx.client("athena")
    wg_a = ctx.unique_name("sim2real-athena-wga-")
    wg_b = ctx.unique_name("sim2real-athena-wgb-")
    wg_tags = [{"Key": "sim2real", "Value": "list-query-executions-reflects-workgroup-scope"}]
    athena.create_work_group(Name=wg_a, Tags=wg_tags)
    athena.create_work_group(Name=wg_b, Tags=wg_tags)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_a, RecursiveDeleteOption=True))
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_b, RecursiveDeleteOption=True))

    qid = athena.start_query_execution(
        QueryString="SELECT 'scoped-to-a'",
        WorkGroup=wg_a,
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]
    _poll_query_execution(ctx, qid)

    ids_in_a = athena.list_query_executions(WorkGroup=wg_a)["QueryExecutionIds"]
    ids_in_b = athena.list_query_executions(WorkGroup=wg_b)["QueryExecutionIds"]
    assert qid in ids_in_a, (
        f"query {qid} was submitted to workgroup {wg_a} but ListQueryExecutions(WorkGroup="
        f"{wg_a}) did not return it: {ids_in_a}"
    )
    assert qid not in ids_in_b, (
        f"query {qid} was submitted to workgroup {wg_a}, not {wg_b}, but "
        f"ListQueryExecutions(WorkGroup={wg_b}) returned it anyway: {ids_in_b}"
    )


def _create_results_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "list-query-executions-reflects-workgroup-scope"},
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
