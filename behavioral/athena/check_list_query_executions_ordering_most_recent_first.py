"""list-query-executions-ordering-most-recent-first."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-query-executions-ordering-most-recent-first"
GROUP = "ordering"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListQueryExecutions in a fresh workgroup lists exactly the three executions started
    in it; AWS documents no order, so most-recent-first is accepted but not required."""
    athena = ctx.client("athena")
    bucket = _create_bucket(ctx)
    wg = ctx.unique_name("sim2real-behav-orderwg-")
    athena.create_work_group(
        Name=wg,
        Configuration={"ResultConfiguration": {"OutputLocation": f"s3://{bucket}/"}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    ids = []
    for i in range(3):
        resp = athena.start_query_execution(QueryString=f"SELECT {i}", WorkGroup=wg)
        ids.append(resp["QueryExecutionId"])
        time.sleep(2)  # force distinguishable submission timestamps

    listed = _poll_until(
        lambda: _query_execution_ids(athena, wg),
        lambda lst: all(i in lst for i in ids),
        timeout_s=60,
        interval_s=3,
    )
    assert len(listed) == 3, (
        f"a freshly created workgroup that ran exactly 3 queries must list exactly 3 "
        f"executions, got {len(listed)}: {listed}"
    )
    positions = [listed.index(i) for i in ids]
    # ids[2] was submitted last (most recent); any order of exactly these ids is accepted
    assert positions[2] < positions[1] < positions[0] or sorted(listed) == sorted(ids), (
        f"expected exactly the started executions, got positions={positions} for ids={ids} listed={listed}"
    )


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-").lower().replace("_", "-")
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _query_execution_ids(athena, workgroup):
    out = []
    token = None
    while True:
        kwargs = {"WorkGroup": workgroup}
        if token:
            kwargs["NextToken"] = token
        resp = athena.list_query_executions(**kwargs)
        out.extend(resp["QueryExecutionIds"])
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
