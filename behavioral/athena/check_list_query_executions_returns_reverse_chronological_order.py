"""list-query-executions-returns-reverse-chronological-order."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-query-executions-returns-reverse-chronological-order"
GROUP = "ordering"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListQueryExecutions orders execution ids most-recent-first: three queries started
    sequentially in the same workgroup come back in exactly the reverse of their submission
    order, a distinct guarantee from merely containing the started executions."""
    athena = ctx.client("athena")
    glue = ctx.client("glue")

    bucket = _create_bucket(ctx)
    wg_name = ctx.unique_name("sim2real-behav-qe-wg-")
    athena.create_work_group(
        Name=wg_name,
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/"},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    db_name = ctx.unique_name("sim2real_behav_qe_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    submitted_ids = []
    for i in range(3):
        resp = athena.start_query_execution(
            QueryString=f"SELECT {i}",
            QueryExecutionContext={"Database": db_name},
            WorkGroup=wg_name,
        )
        submitted_ids.append(resp["QueryExecutionId"])
        time.sleep(2)  # ensure distinguishable submission timestamps

    all_ids = _list_all_query_execution_ids(athena, wg_name)
    positions = [all_ids.index(qid) for qid in submitted_ids]

    # Most recently submitted (last in submitted_ids) must appear before the earlier ones.
    assert positions[2] < positions[1] < positions[0], (
        f"ListQueryExecutions did not return reverse-chronological order: "
        f"submitted={submitted_ids} positions={positions} all_ids={all_ids}"
    )


def _list_all_query_execution_ids(athena, workgroup: str) -> list[str]:
    ids: list[str] = []
    token = None
    while True:
        kwargs = {"WorkGroup": workgroup, "MaxResults": 50}
        if token:
            kwargs["NextToken"] = token
        resp = athena.list_query_executions(**kwargs)
        ids.extend(resp.get("QueryExecutionIds", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-qe-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        objects = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
    )
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
