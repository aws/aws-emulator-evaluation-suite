"""list-query-executions-pagination-no-duplicates."""
from __future__ import annotations

import math
import time
from collections import Counter

from behavioral_harness import tags

CHECK = "list-query-executions-pagination-no-duplicates"
GROUP = "ordering"
SERVICES = ["athena"]


def _create_results_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-res-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket,
                Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
            )
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _list_all_query_execution_ids(athena, workgroup: str) -> tuple[list[str], int]:
    ids: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"WorkGroup": workgroup, "MaxResults": 2}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = athena.list_query_executions(**kwargs)
        pages += 1
        ids.extend(resp.get("QueryExecutionIds", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return ids, pages


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListQueryExecutions across multiple pages contains each started query id exactly once."""
    athena = ctx.client("athena")
    bucket = _create_results_bucket(ctx)
    workgroup = ctx.unique_name("sim2real-wg-")
    athena.create_work_group(Name=workgroup, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(
        lambda: athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True)
    )

    expected_ids = []
    for i in range(6):
        resp = athena.start_query_execution(
            QueryString="SELECT 1",
            WorkGroup=workgroup,
            ResultConfiguration={"OutputLocation": f"s3://{bucket}/out/"},
        )
        expected_ids.append(resp["QueryExecutionId"])

    deadline = time.monotonic() + 60.0
    all_ids: list[str] = []
    counts = Counter()
    pages = 0
    while time.monotonic() < deadline:
        all_ids, pages = _list_all_query_execution_ids(athena, workgroup)
        counts = Counter(all_ids)
        if all(counts.get(qid, 0) >= 1 for qid in expected_ids):
            break
        time.sleep(2.0)

    assert all(counts.get(qid, 0) >= 1 for qid in expected_ids), (
        f"expected ids {sorted(expected_ids)} to all appear, saw counts {dict(counts)}"
    )
    for qid in expected_ids:
        assert counts[qid] == 1, f"query execution {qid} appeared {counts[qid]} times across pages"
    assert set(counts) <= set(expected_ids), (
        f"listing returned query execution ids this check never started: "
        f"{sorted(set(counts) - set(expected_ids))}"
    )
    min_pages = math.ceil(len(expected_ids) / 2)
    assert pages >= min_pages, (
        f"expected MaxResults=2 to force at least {min_pages} pages for "
        f"{len(expected_ids)} executions, saw {pages} page(s) — pagination may not be enforced"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
