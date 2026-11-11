"""workgroup-default-output-location-used-for-query."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "workgroup-default-output-location-used-for-query"
GROUP = "workgroup"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query submitted to a workgroup that has a configured default ResultConfiguration
    OutputLocation, without specifying its own ResultConfiguration, is executed against and
    writes its results under exactly that workgroup-configured S3 prefix."""
    bucket = _create_results_bucket(ctx)
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    wg_name = ctx.unique_name("sim2real-athena-wg-")
    prefix = f"s3://{bucket}/wg-default/"
    athena.create_work_group(
        Name=wg_name,
        Configuration={
            "ResultConfiguration": {"OutputLocation": prefix},
            "EnforceWorkGroupConfiguration": True,
        },
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    qid = athena.start_query_execution(
        QueryString="SELECT 42 AS answer",
        WorkGroup=wg_name,
    )["QueryExecutionId"]
    execution = _poll_query_execution(ctx, qid)
    assert execution["Status"]["State"] == "SUCCEEDED", execution["Status"]

    output_location = execution["ResultConfiguration"]["OutputLocation"]
    assert output_location.startswith(prefix), output_location

    key = output_location[len(f"s3://{bucket}/"):]
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
    assert "answer" in body and "42" in body, body


def _create_results_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)

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
