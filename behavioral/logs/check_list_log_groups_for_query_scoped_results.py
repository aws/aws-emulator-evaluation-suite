"""list-log-groups-for-query-scoped-results."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "list-log-groups-for-query-scoped-results"
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListLogGroupsForQuery returns the log group(s) actually analyzed by a StartQuery run."""
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-logs-lgfq-")
    log_stream_name = ctx.unique_name("sim2real-logs-lgfq-stream-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    logs.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)

    # A second, real, populated log group that the query never names. It exists so the
    # "not scoped in" assertion below has an actual candidate that a target ignoring the
    # query's scope could wrongly surface, rather than a name nothing ever created.
    other_name = ctx.unique_name("sim2real-logs-lgfq-other-")
    other_stream_name = ctx.unique_name("sim2real-logs-lgfq-other-stream-")
    logs.create_log_group(logGroupName=other_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=other_name))
    logs.create_log_stream(logGroupName=other_name, logStreamName=other_stream_name)

    marker = f"sim2real-{uuid.uuid4().hex}"
    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=log_group_name,
        logStreamName=log_stream_name,
        logEvents=[{"timestamp": now_ms, "message": f"lgfq probe {marker}"}],
    )
    logs.put_log_events(
        logGroupName=other_name,
        logStreamName=other_stream_name,
        logEvents=[{"timestamp": now_ms, "message": f"lgfq unrelated probe {marker}"}],
    )

    query_id = logs.start_query(
        logGroupName=log_group_name,
        startTime=now_ms // 1000 - 300,
        endTime=now_ms // 1000 + 300,
        queryString="fields @timestamp, @message | limit 5",
    )["queryId"]

    _poll_until(
        lambda: logs.get_query_results(queryId=query_id)["status"],
        lambda s: s in ("Complete", "Failed", "Cancelled", "Timeout"),
        timeout_s=120.0,
        interval_s=2.0,
    )

    identifiers = logs.list_log_groups_for_query(queryId=query_id)["logGroupIdentifiers"]
    assert len(identifiers) >= 1
    matched = [
        ident
        for ident in identifiers
        if ident == log_group_name or ident.split(":log-group:")[-1].split(":")[0] == log_group_name
    ]
    assert matched, (
        f"expected {log_group_name} among logGroupIdentifiers analyzed by query {query_id}, "
        f"got {identifiers}"
    )

    # other_name has real, matching-shaped data and exists at query time, so a target that
    # scopes StartQuery loosely (e.g. by account/region rather than by named log group) has
    # a real chance of surfacing it here — unlike a name that was never created.
    unrelated = [
        ident
        for ident in identifiers
        if ident == other_name or ident.split(":log-group:")[-1].split(":")[0] == other_name
    ]
    assert not unrelated, (
        f"unrelated but populated log group {other_name} unexpectedly scoped into query "
        f"{query_id}, got {identifiers}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
