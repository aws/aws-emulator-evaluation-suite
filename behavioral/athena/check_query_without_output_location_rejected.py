"""query-without-output-location-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-without-output-location-rejected"
GROUP = "server-side"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQueryExecution on a workgroup with no output location and no ResultConfiguration is
    rejected with InvalidRequestException and creates no execution; with an OutputLocation it runs."""
    athena = ctx.client("athena")
    bucket = _create_bucket(ctx)
    wg_name = ctx.unique_name("sim2real-athena-wg-")

    # Workgroup created WITHOUT any ResultConfiguration -- no server-side default location.
    athena.create_work_group(Name=wg_name, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    before_ids = set(athena.list_query_executions(WorkGroup=wg_name).get("QueryExecutionIds", []))

    code, message = _error(lambda: athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg_name))
    assert code == "InvalidRequestException", f"unexpected error code: {code}"
    # The double space after "location for" is in the message AWS returns.
    assert message == (
        "No output location provided. You did not provide an output location for  your query "
        "results. Either specify an S3 bucket location or enable Athena managed query results "
        "in your workgroup settings."
    ), f"unexpected missing-output-location message: {message!r}"

    after_ids = set(athena.list_query_executions(WorkGroup=wg_name).get("QueryExecutionIds", []))
    assert after_ids == before_ids, "a query execution was created despite the rejected request"

    # positive control: same workgroup, but now with a client-supplied output location
    exec_id = athena.start_query_execution(
        QueryString="SELECT 1",
        WorkGroup=wg_name,
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/client-output/"},
    )["QueryExecutionId"]
    state = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=exec_id)["QueryExecution"]["Status"]["State"],
        lambda s: s in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=120,
        interval_s=3,
    )
    assert state == "SUCCEEDED", f"positive control query did not succeed, state={state}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    instead: accepting a call AWS refuses is a distinct failure, not an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-out-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        # S3's CreateBucket rejects an explicit LocationConstraint matching the default region.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
