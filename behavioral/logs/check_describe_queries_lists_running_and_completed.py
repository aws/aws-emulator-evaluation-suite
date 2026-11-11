"""describe-queries-lists-running-and-completed."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-queries-lists-running-and-completed"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A StartQuery execution transitions through DescribeQueries' status field (e.g.
    Scheduled/Running -> Complete) and that terminal status matches GetQueryResults."""
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-behav-query-")
    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    stream_name = "stream-1"
    logs.create_log_stream(logGroupName=log_group, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    events = [
        {"timestamp": now_ms - (5 - i) * 1000, "message": f"query-test-event-{i}"}
        for i in range(5)
    ]
    logs.put_log_events(logGroupName=log_group, logStreamName=stream_name, logEvents=events)

    start_time = int(time.time()) - 3600
    end_time = int(time.time()) + 60
    query_id = logs.start_query(
        logGroupName=log_group,
        startTime=start_time,
        endTime=end_time,
        queryString="fields @timestamp, @message | sort @timestamp asc | limit 100",
    )["queryId"]
    ctx.on_cleanup(lambda: _safe_stop_query(logs, query_id))

    # DescribeQueries must surface the execution while it is still in flight —
    # not only once it lands on Complete — or "lists running" is untested.
    immediate = logs.describe_queries(logGroupName=log_group)["queries"]
    immediate_ids = {q["queryId"] for q in immediate}
    assert query_id in immediate_ids, (
        f"queryId {query_id} not present in DescribeQueries immediately after StartQuery: {immediate_ids}"
    )

    observed_statuses: list[str] = []
    deadline = time.monotonic() + 60.0
    final_status = None
    while time.monotonic() < deadline:
        desc = logs.describe_queries(logGroupName=log_group)
        matches = [q for q in desc.get("queries", []) if q["queryId"] == query_id]
        assert matches, f"queryId {query_id} not present in DescribeQueries output"
        status = matches[0]["status"]
        observed_statuses.append(status)
        if status in ("Complete", "Failed", "Cancelled", "Timeout"):
            final_status = status
            break
        time.sleep(0.5)

    assert final_status == "Complete", (
        f"query did not reach Complete within timeout, observed statuses: {observed_statuses}"
    )

    results = logs.get_query_results(queryId=query_id)
    assert results["status"] == "Complete", (
        f"GetQueryResults status {results['status']} does not match terminal Complete"
    )

    desc_final = logs.describe_queries(logGroupName=log_group)
    final_matches = [q for q in desc_final.get("queries", []) if q["queryId"] == query_id]
    assert final_matches and final_matches[0]["status"] == "Complete", (
        "DescribeQueries did not retain the Complete status for the finished query"
    )
    assert final_matches[0]["logGroupName"] == log_group, (
        f"DescribeQueries logGroupName {final_matches[0]['logGroupName']!r} != {log_group!r}"
    )

    # The status filter must agree with the unfiltered listing: present under
    # status=Complete, and no longer present under status=Running.
    completed_filtered = logs.describe_queries(logGroupName=log_group, status="Complete")["queries"]
    completed_ids = {q["queryId"] for q in completed_filtered}
    assert query_id in completed_ids, (
        f"queryId {query_id} not present in DescribeQueries(status=Complete): {completed_ids}"
    )
    running_filtered = logs.describe_queries(logGroupName=log_group, status="Running")["queries"]
    running_ids = {q["queryId"] for q in running_filtered}
    assert query_id not in running_ids, (
        f"completed queryId {query_id} unexpectedly still listed under DescribeQueries(status=Running)"
    )


def _safe_stop_query(logs, query_id: str) -> None:
    try:
        logs.stop_query(queryId=query_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
