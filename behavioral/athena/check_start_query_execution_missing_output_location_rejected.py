"""start-query-execution-missing-output-location-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-query-execution-missing-output-location-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQueryExecution with no output location anywhere is rejected with InvalidRequestException
    and ListQueryExecutions shows no new id; with an OutputLocation the same query reaches SUCCEEDED."""
    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg_name)  # no Configuration -> no default OutputLocation
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    before_ids = set(athena.list_query_executions(WorkGroup=wg_name).get("QueryExecutionIds", []))

    captured = {}

    def _attempt():
        captured["resp"] = athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg_name)

    err = _error(_attempt)
    expected = (
        "InvalidRequestException",
        "No output location provided. You did not provide an output location for  your query "
        "results. Either specify an S3 bucket location or enable Athena managed query results "
        "in your workgroup settings.",
    )
    assert err == expected, f"expected {expected!r}, got {err!r}"
    assert "resp" not in captured, "a QueryExecutionId should not have been allocated"

    after_ids = set(athena.list_query_executions(WorkGroup=wg_name).get("QueryExecutionIds", []))
    assert after_ids == before_ids, (
        f"a query execution appeared in ListQueryExecutions despite the rejected request: "
        f"new ids {after_ids - before_ids}"
    )

    # Positive control: the same query succeeds once an OutputLocation is supplied, and an
    # independent GetQueryExecution read (not the mutating call's own response) confirms it
    # actually ran to completion.
    qid = athena.start_query_execution(
        QueryString="SELECT 1",
        WorkGroup=wg_name,
        ResultConfiguration={"OutputLocation": _fallback_bucket_location(ctx)},
    )["QueryExecutionId"]
    assert qid, "positive-control StartQueryExecution did not return a QueryExecutionId"

    state = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"],
        lambda s: s in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=120,
        interval_s=3,
    )
    assert state == "SUCCEEDED", f"positive-control query did not succeed, state={state!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _fallback_bucket_location(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        # us-east-1 rejects CreateBucketConfiguration/LocationConstraint outright; every other
        # region requires it. Not a hardcoded region choice -- ctx.region drives bucket placement.
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
    return f"s3://{bucket}/results/"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
