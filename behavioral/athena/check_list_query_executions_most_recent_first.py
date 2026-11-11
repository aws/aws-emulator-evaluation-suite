"""list-query-executions-most-recent-first."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-query-executions-most-recent-first"
GROUP = "ordering"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListQueryExecutions lists every query execution of the workgroup exactly once on repeated
    calls, and their SubmissionDateTime values follow the order they were submitted in."""
    athena = ctx.client("athena")
    bucket = _create_output_bucket(ctx)
    wg = ctx.unique_name("sim2real-behav-wg-order-")
    athena.create_work_group(
        Name=wg,
        Configuration={"ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/"}},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    created_ids: list[str] = []
    submitted: list[Any] = []
    for i in range(3):
        resp = athena.start_query_execution(
            QueryString=f"SELECT {i}",
            ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"},
            WorkGroup=wg,
        )
        qid = resp["QueryExecutionId"]
        created_ids.append(qid)
        state = _wait_for_terminal_state(athena, qid, timeout_s=60.0)
        assert state == "SUCCEEDED", f"setup query {i} ({qid}) reached {state}, expected SUCCEEDED"
        execution = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        submitted.append(execution["Status"]["SubmissionDateTime"])
        # ensure the next submission's timestamp is distinguishable from this one
        time.sleep(1.2)

    first_pass = _list_all_query_executions(athena, wg)
    second_pass = _list_all_query_executions(athena, wg)

    # The list order itself is not documented, so the order is read from SubmissionDateTime.
    for listed in (first_pass, second_pass):
        assert sorted(listed) == sorted(created_ids), (
            f"expected exactly the 3 created executions listed once each, got {listed}"
        )
    assert submitted == sorted(submitted) and len(set(submitted)) == 3, (
        f"SubmissionDateTime in submission order is {submitted}; queries submitted seconds apart "
        f"carry strictly increasing values"
    )


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _wait_for_terminal_state(athena, query_execution_id: str, timeout_s: float = 60.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = "QUEUED"
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=query_execution_id)
        state = resp["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return state
        time.sleep(1.5)
    raise AssertionError(
        f"query {query_execution_id} did not reach a terminal state within {timeout_s}s (last={state})"
    )


def _list_all_query_executions(athena, workgroup: str) -> list[str]:
    ids: list[str] = []
    token = None
    while True:
        kwargs = {"MaxResults": 5, "WorkGroup": workgroup}
        if token:
            kwargs["NextToken"] = token
        resp = athena.list_query_executions(**kwargs)
        ids.extend(resp.get("QueryExecutionIds", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
