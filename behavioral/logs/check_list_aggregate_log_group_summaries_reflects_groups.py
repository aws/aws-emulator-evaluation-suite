"""list-aggregate-log-group-summaries-reflects-groups."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "list-aggregate-log-group-summaries-reflects-groups"
GROUP = "state-machine"
SERVICES = ["logs"]


def _poll_until(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _total_log_group_count(logs, pattern: str) -> int:
    total = 0
    next_token = None
    while True:
        kwargs = {"groupBy": "DATA_SOURCE_NAME_AND_TYPE", "logGroupNamePattern": pattern}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = logs.list_aggregate_log_group_summaries(**kwargs)
        for summary in resp["aggregateLogGroupSummaries"]:
            total += summary["logGroupCount"]
        next_token = resp.get("nextToken")
        if not next_token:
            return total


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAggregateLogGroupSummaries' counts grow by exactly one when a matching log group is
    created and receives a log event, and shrink back by one once it is deleted."""
    logs = ctx.client("logs")
    token = uuid.uuid4().hex[:10]
    log_group_name = f"/sim2real/agg/{token}"

    before = _total_log_group_count(logs, token)
    assert before == 0, f"expected zero log groups matching {token} before creation, got {before}"

    logs.create_log_group(logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    # The server-side aggregation index only indexes data sources that have actual indexed log data
    # -- a log group with no log events is never surfaced by ListAggregateLogGroupSummaries, no
    # matter how long we poll. Put an event into the group so the aggregate view has something to
    # index.
    stream_name = "sim2real-probe-stream"
    logs.create_log_stream(logGroupName=log_group_name, logStreamName=stream_name)
    logs.put_log_events(
        logGroupName=log_group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": "sim2real probe event"}],
    )

    # This aggregate view is derived asynchronously from the underlying log groups and can lag
    # by minutes (comparable to other CloudWatch Logs aggregate statistics), so poll with a
    # generous bounded window instead of asserting on the first read.
    after = _poll_until(
        lambda: _total_log_group_count(logs, token),
        lambda n: n == 1,
        timeout_s=200.0,
        interval_s=10.0,
    )
    assert after == 1, f"expected exactly one log group matching {token} after creation, got {after}"

    logs.delete_log_group(logGroupName=log_group_name)

    after_delete = _poll_until(
        lambda: _total_log_group_count(logs, token),
        lambda n: n == 0,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert after_delete == 0, (
        f"expected zero log groups matching {token} after deletion, got {after_delete}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
