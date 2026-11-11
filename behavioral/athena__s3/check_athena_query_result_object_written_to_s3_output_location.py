"""athena-query-result-object-written-to-s3-output-location."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "athena-query-result-object-written-to-s3-output-location"
GROUP = "arn-resolution"
SERVICES = ["athena", "s3"]


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags():
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv():
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind):
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _object_exists(s3, bucket, key):
    """True once HeadObject finds the object, False while it 404s; any other refusal raises."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "404":
            raise
        return False
    return True


def _delete_bucket(s3, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, kind="bkt"):
    """Create a uniquely-named, region-correct bucket; register empty+delete teardown."""
    s3 = ctx.client("s3")
    name = _xname(ctx, kind)
    params = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(ctx.client("s3"), name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    return name


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Athena writes the result CSV with the query's rows to <OutputLocation><query_id>.csv plus a
    .metadata sibling, and an enforcing workgroup's location overrides a client-supplied one silently."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, "athena-results")
    decoy_bucket = _new_bucket(ctx, "athena-decoy")
    prefix = "results/"
    output_location = f"s3://{bucket}/{prefix}"

    wg = _xname(ctx, "wg")
    athena.create_work_group(
        Name=wg,
        Configuration={
            "ResultConfiguration": {"OutputLocation": output_location},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(
        lambda: ctx.client("athena").delete_work_group(
            WorkGroup=wg, RecursiveDeleteOption=True
        )
    )

    query = "SELECT 'sim2real-xsvc' AS marker"
    qid = athena.start_query_execution(QueryString=query, WorkGroup=wg)["QueryExecutionId"]
    state = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"],
        lambda s: s["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=180.0,
        interval_s=3.0,
        description="the query reaches a terminal state",
    )
    assert state["State"] == "SUCCEEDED", f"expected SUCCEEDED, got {state!r}"

    execution = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
    reported = execution["ResultConfiguration"]["OutputLocation"]
    assert reported == f"{output_location}{qid}.csv", (
        f"expected the result location to be {output_location}{qid}.csv, got {reported!r}"
    )

    # The cross-boundary observable: the object really exists in S3, with the query's rows in it.
    result_key = f"{prefix}{qid}.csv"
    _poll_until(
        lambda: _object_exists(s3, bucket, result_key),
        lambda exists: exists,
        timeout_s=120.0,
        interval_s=3.0,
        description=f"Athena writes the result object s3://{bucket}/{result_key}",
    )
    csv_body = s3.get_object(Bucket=bucket, Key=result_key)["Body"].read().decode()
    assert '"marker"' in csv_body, (
        f"the result CSV must contain the column header row: {csv_body!r}"
    )
    assert "sim2real-xsvc" in csv_body, (
        f"the result CSV must contain the query's data row: {csv_body!r}"
    )
    keys = [
        o["Key"]
        for o in s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])
    ]
    assert f"{result_key}.metadata" in keys, (
        f"Athena must write the result metadata sibling alongside the CSV: {keys!r}"
    )

    # Precedence: with EnforceWorkGroupConfiguration the client's location is overridden, not
    # honoured and not rejected -- and nothing is written to the bucket the client asked for.
    qid2 = athena.start_query_execution(
        QueryString=query,
        WorkGroup=wg,
        ResultConfiguration={"OutputLocation": f"s3://{decoy_bucket}/ignored/"},
    )["QueryExecutionId"]
    state2 = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=qid2)["QueryExecution"]["Status"],
        lambda s: s["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=180.0,
        interval_s=3.0,
        description="the second query reaches a terminal state",
    )
    assert state2["State"] == "SUCCEEDED", f"expected SUCCEEDED, got {state2!r}"
    reported2 = athena.get_query_execution(QueryExecutionId=qid2)["QueryExecution"][
        "ResultConfiguration"
    ]["OutputLocation"]
    assert reported2 == f"{output_location}{qid2}.csv", (
        f"the enforcing workgroup's location must win, got {reported2!r}"
    )
    _poll_until(
        lambda: _object_exists(s3, bucket, f"{prefix}{qid2}.csv"),
        lambda exists: exists,
        timeout_s=120.0,
        interval_s=3.0,
        description="the overridden query still writes to the workgroup's location",
    )
    decoy_keys = s3.list_objects_v2(Bucket=decoy_bucket).get("Contents", [])
    assert decoy_keys == [], (
        f"nothing may be written to the client-supplied location when the workgroup enforces its "
        f"own: {decoy_keys!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
