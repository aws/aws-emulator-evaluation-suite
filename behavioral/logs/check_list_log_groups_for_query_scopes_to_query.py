"""list-log-groups-for-query-scopes-to-query."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-log-groups-for-query-scopes-to-query"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListLogGroupsForQuery returns exactly the log groups touched by a cross-group StartQuery."""
    logs = ctx.client("logs")
    prefix = ctx.unique_name("sim2real-behav-llgfq-")
    group_a = f"{prefix}-a"
    group_b = f"{prefix}-b"
    stream_name = "stream-1"
    for group in (group_a, group_b):
        logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
        ctx.on_cleanup(lambda g=group: logs.delete_log_group(logGroupName=g))
        logs.create_log_stream(logGroupName=group, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    for group, msg in ((group_a, "hello-from-a"), (group_b, "hello-from-b")):
        logs.put_log_events(
            logGroupName=group,
            logStreamName=stream_name,
            logEvents=[{"timestamp": now_ms, "message": msg}],
        )

    start_time_s = (now_ms // 1000) - 300
    end_time_s = (now_ms // 1000) + 300
    query_id = logs.start_query(
        logGroupNames=[group_a, group_b],
        startTime=start_time_s,
        endTime=end_time_s,
        queryString="fields @timestamp, @message",
    )["queryId"]

    result = _poll_until(
        lambda: logs.get_query_results(queryId=query_id),
        lambda r: r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert result["status"] == "Complete", f"query ended in {result['status']!r}"

    identifiers = logs.list_log_groups_for_query(queryId=query_id)["logGroupIdentifiers"]
    assert len(identifiers) == 2, f"expected exactly the 2 queried log groups, got {identifiers}"
    for group in (group_a, group_b):
        assert any(group in ident for ident in identifiers), (
            f"expected {group!r} to appear in {identifiers}"
        )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
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
