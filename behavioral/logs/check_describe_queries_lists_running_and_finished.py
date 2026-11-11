"""describe-queries-lists-running-and-finished."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-queries-lists-running-and-finished"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeQueries reports StartQuery executions through Complete and Cancelled transitions."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-dq-")
    stream_name = "stream-1"
    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": now_ms, "message": "hello-describe-queries"}],
    )
    start_time_s = (now_ms // 1000) - 300
    end_time_s = (now_ms // 1000) + 300

    # --- part 1: a query that runs to Complete shows up under DescribeQueries(status=Complete) ---
    query_id = logs.start_query(
        logGroupName=group_name,
        startTime=start_time_s,
        endTime=end_time_s,
        queryString="fields @timestamp, @message",
    )["queryId"]

    result = _poll_until(
        lambda: logs.get_query_results(queryId=query_id),
        lambda r: r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"),
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=1.0,
    )
    if result["status"] not in ("Complete", "Failed", "Cancelled", "Timeout") and _budget_spent(ctx):
        raise TimeoutError(f"query {query_id} to finish: the run budget ended first; not graded")
    assert result["status"] == "Complete", f"query ended in {result['status']!r}"

    completed = _poll_until(
        lambda: {q["queryId"] for q in logs.describe_queries(logGroupName=group_name, status="Complete").get("queries", [])},
        lambda ids: query_id in ids,
        timeout_s=_budget_s(ctx, 30.0),
        interval_s=1.0,
    )
    if query_id not in completed and _budget_spent(ctx):
        raise TimeoutError(f"{query_id} in DescribeQueries(status=Complete): the run budget ended first; not graded")
    assert query_id in completed, f"expected {query_id} in DescribeQueries(status=Complete): {completed}"

    # --- part 2: a query stopped before it finishes transitions to Cancelled ---
    # A query that finishes before the stop lands is refused (InvalidParameterException) or
    # reported success=false; it is drained and retried with a fresh query.
    cancelled_query_id = None
    for _ in range(5):
        candidate = logs.start_query(
            logGroupName=group_name,
            startTime=start_time_s,
            endTime=end_time_s,
            queryString="fields @timestamp, @message",
        )["queryId"]
        try:
            stop_resp = logs.stop_query(queryId=candidate)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            stop_resp = {}
        if stop_resp.get("success"):
            cancelled_query_id = candidate
            break
        # too fast to catch mid-flight; let it finish and try again with a fresh query
        drained = _poll_until(
            lambda cid=candidate: logs.get_query_results(queryId=cid)["status"],
            lambda s: s in ("Complete", "Failed", "Cancelled", "Timeout"),
            timeout_s=_budget_s(ctx, 30.0),
            interval_s=1.0,
        )
        if drained not in ("Complete", "Failed", "Cancelled", "Timeout") and _budget_spent(ctx):
            raise TimeoutError(f"query {candidate} to finish: the run budget ended first; not graded")
    assert cancelled_query_id is not None, "never managed to StopQuery a query before it finished"

    cancelled = _poll_until(
        lambda: {q["queryId"] for q in logs.describe_queries(logGroupName=group_name, status="Cancelled").get("queries", [])},
        lambda ids: cancelled_query_id in ids,
        timeout_s=_budget_s(ctx, 30.0),
        interval_s=1.0,
    )
    if cancelled_query_id not in cancelled and _budget_spent(ctx):
        raise TimeoutError(
            f"{cancelled_query_id} in DescribeQueries(status=Cancelled): the run budget ended first; not graded"
        )
    assert cancelled_query_id in cancelled, (
        f"expected {cancelled_query_id} in DescribeQueries(status=Cancelled): {cancelled}"
    )

    # --- part 3: the status filter excludes, not just includes — a target that ignores
    # `status` and returns every query for the group would otherwise pass every assertion
    # above without ever honoring the filter. ---
    assert query_id not in cancelled, (
        f"the completed query {query_id} leaked into DescribeQueries(status=Cancelled): {cancelled}"
    )
    completed_after_cancel = {
        q["queryId"]
        for q in logs.describe_queries(logGroupName=group_name, status="Complete").get("queries", [])
    }
    assert cancelled_query_id not in completed_after_cancel, (
        f"the cancelled query {cancelled_query_id} leaked into DescribeQueries(status=Complete): "
        f"{completed_after_cancel}"
    )

    all_ids = {q["queryId"] for q in logs.describe_queries(logGroupName=group_name).get("queries", [])}
    assert {query_id, cancelled_query_id} <= all_ids, (
        f"expected both queries in unfiltered DescribeQueries: {all_ids}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
