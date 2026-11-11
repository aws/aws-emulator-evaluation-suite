"""describe-queries-lists-inflight-and-completed."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "describe-queries-lists-inflight-and-completed"
GROUP = "state-machine"
SERVICES = ["logs"]


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeQueries lists a query right after StartQuery, then again once it Completes."""
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-logs-queries-")
    log_stream_name = ctx.unique_name("sim2real-logs-queries-stream-")
    logs.create_log_group(logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    logs.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)

    marker = f"sim2real-{uuid.uuid4().hex}"
    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=log_group_name,
        logStreamName=log_stream_name,
        logEvents=[{"timestamp": now_ms, "message": f"describe-queries probe {marker}"}],
    )

    query_id = logs.start_query(
        logGroupName=log_group_name,
        startTime=now_ms // 1000 - 300,
        endTime=now_ms // 1000 + 300,
        queryString="fields @timestamp, @message | limit 5",
    )["queryId"]

    # Immediately after starting, DescribeQueries (scoped to this log group) must already
    # surface the query, in a non-terminal-or-terminal-but-present status.
    immediate = logs.describe_queries(logGroupName=log_group_name)["queries"]
    immediate_ids = {q["queryId"] for q in immediate}
    assert query_id in immediate_ids, (
        f"queryId {query_id} not present in DescribeQueries immediately after StartQuery"
    )

    final_status = _poll_until(
        lambda: logs.get_query_results(queryId=query_id)["status"],
        lambda s: s in ("Complete", "Failed", "Cancelled", "Timeout"),
        timeout_s=120.0,
        interval_s=2.0,
    )
    assert final_status == "Complete", f"query ended in unexpected status {final_status}"

    completed = logs.describe_queries(logGroupName=log_group_name, status="Complete")["queries"]
    completed_ids = {q["queryId"] for q in completed}
    assert query_id in completed_ids, (
        f"queryId {query_id} not present in DescribeQueries(status=Complete) after completion"
    )
    matching = [q for q in completed if q["queryId"] == query_id][0]
    assert matching["logGroupName"] == log_group_name, (
        f"expected logGroupName {log_group_name!r} on completed query, got {matching['logGroupName']!r}"
    )
    assert matching["status"] == "Complete", (
        f"expected status 'Complete' on the DescribeQueries(status=Complete) entry, got {matching['status']!r}"
    )

    # And it must no longer show up under a status filter it doesn't hold.
    running = logs.describe_queries(logGroupName=log_group_name, status="Running")["queries"]
    running_ids = {q["queryId"] for q in running}
    assert query_id not in running_ids, (
        f"queryId {query_id} unexpectedly present in DescribeQueries(status=Running) after completion"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
