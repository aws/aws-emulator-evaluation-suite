"""athena-workgroup-output-location-override-s3-positive."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "athena-workgroup-output-location-override-s3-positive"
GROUP = "result-delivery"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A workgroup with EnforceWorkGroupConfiguration=True and a ResultConfiguration
    S3 output location overrides the per-query OutputLocation: the result object is
    written to the workgroup's bucket, not the one requested on the query."""
    wg_bucket = _create_bucket(ctx, "wgout")
    per_query_bucket = _create_bucket(ctx, "queryout")
    wg_prefix = "wg-results/"
    query_prefix = "query-results/"
    wg_output_location = f"s3://{wg_bucket}/{wg_prefix}"
    per_query_output_location = f"s3://{per_query_bucket}/{query_prefix}"

    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(
        Name=wg_name,
        Configuration={
            "ResultConfiguration": {"OutputLocation": wg_output_location},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name))

    qid, state, exec_resp = _run_query(
        ctx,
        query="SELECT 'sim2real-wg-override' AS marker",
        output_location=per_query_output_location,
        workgroup=wg_name,
    )
    assert state == "SUCCEEDED", f"query did not succeed: {exec_resp['Status']}"

    # The execution record itself reports the *effective* output location used.
    effective_location = exec_resp["ResultConfiguration"]["OutputLocation"]
    assert effective_location.startswith(f"s3://{wg_bucket}/"), effective_location

    s3 = ctx.client("s3")
    wg_key = f"{wg_prefix}{qid}.csv"
    head = s3.head_object(Bucket=wg_bucket, Key=wg_key)
    assert head["ContentLength"] > 0, f"expected a non-empty result object, got {head!r}"

    query_key = f"{query_prefix}{qid}.csv"
    code = _error_code(lambda: s3.head_object(Bucket=per_query_bucket, Key=query_key))
    assert code == "404", f"expected 404 (no object at the overridden location), got {code!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because a target
    that wrote the result to the client-requested (overridden) location too is failing the
    enforcement contract under test."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError(
        f"expected no object at the overridden per-query location, but head_object "
        f"succeeded: {result!r}"
    )


def _create_bucket(ctx, kind: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-athena-{kind}-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _run_query(
    ctx,
    query: str,
    output_location: str | None = None,
    database: str | None = None,
    workgroup: str | None = None,
    timeout_s: float = 120.0,
):
    athena = ctx.client("athena")
    kwargs: dict = {"QueryString": query}
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    if output_location:
        kwargs["ResultConfiguration"] = {"OutputLocation": output_location}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    resp = athena.start_query_execution(**kwargs)
    qid = resp["QueryExecutionId"]
    deadline = time.monotonic() + timeout_s
    exec_resp = None
    state = None
    while time.monotonic() < deadline:
        exec_resp = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = exec_resp["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return qid, state, exec_resp
        time.sleep(2)
    raise AssertionError(f"query {qid} did not finish in {timeout_s}s, last state {state}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
