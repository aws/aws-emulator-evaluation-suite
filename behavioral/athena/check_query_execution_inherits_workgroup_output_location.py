"""query-execution-inherits-workgroup-output-location."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-execution-inherits-workgroup-output-location"
GROUP = 'query-execution'
SERVICES = ['athena']

def _empty_and_delete_bucket(s3, bucket):
    # The query started in run() is still async when cleanup fires (we never wait for it to
    # finish, since the assertion only needs the inherited config, not the write). If it lands
    # its result object between our list and our delete_bucket, the delete fails with
    # BucketNotEmpty — retry the empty-then-delete pass instead of a single best-effort attempt.
    deadline = time.monotonic() + 30.0
    while True:
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
                objs = page.get("Contents", [])
                if objs:
                    s3.delete_objects(
                        Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                    )
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "BucketNotEmpty" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _output_location(ctx):
    """Create an Athena query-results bucket (region-correct) and return its s3:// prefix."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-results-")
    kwargs = {"Bucket": bucket}
    # us-east-1 rejects a LocationConstraint on create_bucket; every other region requires one.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "query-execution-inherits-workgroup-output-location"}]},
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return f"s3://{bucket}/results/"

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query started without its own ResultConfiguration must inherit the WorkGroup's default OutputLocation."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-behav-wg-inherit-")
    output_loc = _output_location(ctx)
    athena.create_work_group(
        Name=wg,
        Configuration={"ResultConfiguration": {"OutputLocation": output_loc}},
        Tags=[{"Key": "sim2real", "Value": "query-execution-inherits-workgroup-output-location"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    resp = athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg)
    qid = resp["QueryExecutionId"]

    exec_info = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
    inherited = exec_info.get("ResultConfiguration", {}).get("OutputLocation", "")
    assert inherited.startswith(output_loc.rstrip("/")), (
        f"expected query result location to inherit workgroup default {output_loc!r}, got {inherited!r}"
    )

    # Stop the still-async query now rather than let it keep running into cleanup, where a
    # late result write into the output bucket would race the bucket teardown below.
    try:
        athena.stop_query_execution(QueryExecutionId=qid)
    except Exception:
        pass

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
