"""workgroup-disabled-blocks-query-execution-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "workgroup-disabled-blocks-query-execution-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query succeeds in an ENABLED workgroup; DISABLED, the workgroup refuses the identical
    submission with InvalidRequestException and records nothing; re-ENABLED, it succeeds again."""
    bucket = _create_results_bucket(ctx)
    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(
        Name=wg_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))
    output = {"OutputLocation": f"s3://{bucket}/results/"}

    # Positive control first: the identical call succeeds while the workgroup is ENABLED.
    control_qid = athena.start_query_execution(
        QueryString="SELECT 1", WorkGroup=wg_name, ResultConfiguration=output
    )["QueryExecutionId"]
    control = _poll_query_execution(ctx, control_qid)
    # `SELECT 1` in an ENABLED workgroup has no table, permission or syntax question: the only way it
    # does not SUCCEED is that no SQL engine executed it.
    assert control["Status"]["State"] == "SUCCEEDED", (
        f"DATAPLANE_UNIMPLEMENTED: expected the control query in the ENABLED workgroup to SUCCEED, "
        f"so no SQL engine executed it, got {control['Status']!r}")

    athena.update_work_group(WorkGroup=wg_name, State="DISABLED")
    state = athena.get_work_group(WorkGroup=wg_name)["WorkGroup"]["State"]
    assert state == "DISABLED", f"expected DISABLED after UpdateWorkGroup, got {state!r}"

    captured = {}

    def _attempt():
        captured["qid"] = athena.start_query_execution(
            QueryString="SELECT 1",
            WorkGroup=wg_name,
            ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
        )["QueryExecutionId"]

    code, status, message = _error(_attempt)
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException from a DISABLED workgroup, got {code!r}")
    assert status == 400, f"expected HTTP 400 from a DISABLED workgroup, got {status}"
    expected_message = f"WorkGroup {wg_name} is disabled."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    assert "qid" not in captured, "no query should have been started against a disabled workgroup"
    # Effect absent: the workgroup's own history holds only the control query.
    history = _query_ids(athena, wg_name)
    assert history == [control_qid], (
        f"expected the workgroup's query history to hold only the control query, got {len(history)} ids"
    )

    # Positive control: re-enabling the workgroup allows the same request to succeed.
    athena.update_work_group(WorkGroup=wg_name, State="ENABLED")
    state = athena.get_work_group(WorkGroup=wg_name)["WorkGroup"]["State"]
    assert state == "ENABLED", f"expected ENABLED after UpdateWorkGroup, got {state!r}"
    qid = athena.start_query_execution(
        QueryString="SELECT 1",
        WorkGroup=wg_name,
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
    )["QueryExecutionId"]
    execution = _poll_query_execution(ctx, qid)
    assert execution["Status"]["State"] == "SUCCEEDED", (
        f"expected the re-admitted query to SUCCEED, got {execution['Status']!r}")


def _create_results_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-").lower().replace("_", "-")
    kwargs = {}
    # us-east-1 is S3's default region: CreateBucket rejects an explicit LocationConstraint there
    # but requires one everywhere else.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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


def _query_ids(athena, wg_name):
    """Every query execution id recorded in the workgroup."""
    return [
        qid
        for page in athena.get_paginator("list_query_executions").paginate(WorkGroup=wg_name)
        for qid in page["QueryExecutionIds"]
    ]


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


def _error(fn):
    """The botocore Error.Code, HTTP status and Message raised by fn(), or a hard failure if the call
    unexpectedly SUCCEEDS. An emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            err.response["Error"].get("Message") or "",
        )
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
