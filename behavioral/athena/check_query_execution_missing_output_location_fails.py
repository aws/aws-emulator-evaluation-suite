"""query-execution-missing-output-location-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-execution-missing-output-location-fails"
GROUP = 'overly-permissive'
SERVICES = ['athena']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQueryExecution with no output location in the request or the WorkGroup fails with
    InvalidRequestException and allocates no execution; with an OutputLocation the same call succeeds."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-behav-wg-nooutput-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "sim2real", "Value": CHECK}])  # no ResultConfiguration default set
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    before_ids = set(athena.list_query_executions(WorkGroup=wg).get("QueryExecutionIds", []))

    code, message = _error(lambda: athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg))
    assert code == "InvalidRequestException", f"expected InvalidRequestException for missing output location, got {code}"
    # The double space after "location for" is in the message AWS returns.
    assert message == (
        "No output location provided. You did not provide an output location for  your query "
        "results. Either specify an S3 bucket location or enable Athena managed query results "
        "in your workgroup settings."
    ), f"unexpected missing-output-location message: {message!r}"

    after_ids = set(athena.list_query_executions(WorkGroup=wg).get("QueryExecutionIds", []))
    assert after_ids == before_ids, "a query execution was allocated despite the rejected request"

    # restore leg: identical query on the same WorkGroup succeeds once a client-supplied
    # OutputLocation is provided.
    bucket = _create_bucket(ctx)
    exec_id = athena.start_query_execution(
        QueryString="SELECT 1",
        WorkGroup=wg,
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]
    state = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=exec_id)["QueryExecution"]["Status"]["State"],
        lambda s: s in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=120,
        interval_s=3,
    )
    assert state == "SUCCEEDED", f"restored query with OutputLocation did not succeed, state={state}"


def _error(fn):
    """The (code, message) of the ClientError `fn` raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected StartQueryExecution to be rejected but it succeeded")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    import time

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
    name = ctx.unique_name("sim2real-behav-wg-nooutput-").replace("_", "-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)

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
