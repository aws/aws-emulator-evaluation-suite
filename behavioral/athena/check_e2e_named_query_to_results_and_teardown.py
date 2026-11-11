"""e2e-named-query-to-results-and-teardown."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-named-query-to-results-and-teardown"
GROUP = "e2e"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A named query's stored SQL runs to SUCCEEDED with the expected result row, and after
    DeleteNamedQuery GetNamedQuery fails with InvalidRequestException."""
    athena = ctx.client("athena")
    bucket = _create_bucket(ctx)

    wg_name = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(
        Name=wg_name,
        Configuration={"ResultConfiguration": {"OutputLocation": f"s3://{bucket}/"}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    query_string = "SELECT 111 AS answer"
    nq = athena.create_named_query(
        Name=ctx.unique_name("sim2real-behav-nq-"),
        Database="default",
        QueryString=query_string,
        WorkGroup=wg_name,
    )
    named_query_id = nq["NamedQueryId"]

    stored = athena.get_named_query(NamedQueryId=named_query_id)["NamedQuery"]
    assert stored["QueryString"] == query_string, (
        f"expected stored QueryString {query_string!r}, got {stored['QueryString']!r}"
    )
    assert stored["WorkGroup"] == wg_name, (
        f"expected stored WorkGroup {wg_name!r}, got {stored['WorkGroup']!r}"
    )

    resp = athena.start_query_execution(QueryString=stored["QueryString"], WorkGroup=wg_name)
    query_execution_id = resp["QueryExecutionId"]
    qe = _poll_query_execution(ctx, query_execution_id)
    assert qe["Status"]["State"] == "SUCCEEDED", (
        f"expected SUCCEEDED, got {qe['Status']['State']}"
    )

    results = athena.get_query_results(QueryExecutionId=query_execution_id)
    rows = results["ResultSet"]["Rows"]
    values = [r["Data"][0].get("VarCharValue") for r in rows]
    assert "111" in values, f"expected the literal 111 among result rows, got {values}"

    athena.delete_named_query(NamedQueryId=named_query_id)
    code, message = _error(lambda: athena.get_named_query(NamedQueryId=named_query_id))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected = f"NamedQuery: {named_query_id} does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-athena-e2e-").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":  # S3 CreateBucket rejects LocationConstraint for us-east-1 itself
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket,
                Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
            )
    s3.delete_bucket(Bucket=bucket)


def _poll_query_execution(ctx, query_execution_id: str, timeout_s: float = 60.0) -> dict:
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    qe = None
    while time.monotonic() < deadline:
        qe = athena.get_query_execution(QueryExecutionId=query_execution_id)["QueryExecution"]
        if qe["Status"]["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return qe
        time.sleep(1.5)
    raise AssertionError(f"query execution did not reach a terminal state in {timeout_s}s: {qe}")


def _error(fn):
    """Call fn(); return its ClientError (code, message), or fail if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the named query to be gone, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
