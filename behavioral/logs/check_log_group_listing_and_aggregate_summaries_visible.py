"""log-group-listing-and-aggregate-summaries-visible."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "log-group-listing-and-aggregate-summaries-visible"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Newly created log groups appear in ListLogGroups,
    ListAggregateLogGroupSummaries, and ListLogGroupsForQuery."""
    logs = ctx.client("logs")

    # A short random token embedded in the log group name lets us build a
    # tight (<=24 char) regex pattern that can only match this one log group,
    # as required by logGroupNamePattern / dataSources filters.
    token = uuid.uuid4().hex[:12]
    log_group_name = f"/sim2real-behav/{token}"

    before_total = sum(
        s.get("logGroupCount", 0)
        for s in logs.list_aggregate_log_group_summaries(
            groupBy="DATA_SOURCE_NAME_AND_TYPE", logGroupNamePattern=token
        )["aggregateLogGroupSummaries"]
    )
    assert before_total == 0, (
        f"expected zero log groups matching {token} before creation, got {before_total}"
    )

    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _best_effort_delete_log_group(logs, log_group_name))
    described = _poll_until(
        lambda: logs.describe_log_groups(logGroupNamePattern=token)["logGroups"],
        lambda groups: len(groups) > 0,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert described, f"log group not visible in DescribeLogGroups: {described}"
    log_group_arn = described[0]["arn"]

    log_stream_name = ctx.unique_name("stream-")
    logs.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)
    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=log_group_name,
        logStreamName=log_stream_name,
        logEvents=[{"timestamp": now_ms, "message": "sim2real behavioral aggregate-visibility test"}],
    )

    found = _poll_until(
        lambda: logs.list_log_groups(logGroupNamePattern=token)["logGroups"],
        lambda groups: any(g["logGroupName"] == log_group_name for g in groups),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert any(g["logGroupName"] == log_group_name for g in found), (
        f"log group not visible in ListLogGroups: {found}"
    )

    aggregate = _poll_until(
        lambda: logs.list_aggregate_log_group_summaries(
            groupBy="DATA_SOURCE_NAME_AND_TYPE", logGroupNamePattern=token
        )["aggregateLogGroupSummaries"],
        lambda summaries: sum(s.get("logGroupCount", 0) for s in summaries) == 1,
        # Aggregate log-group summaries are computed by a background process
        # that is much more loosely eventually-consistent than the plain
        # ListLogGroups/DescribeLogGroups indexes polled above (comparable to
        # other CloudWatch Logs usage/aggregate statistics, which can lag by
        # many minutes). Give it a generous bounded window rather than the
        # same short timeout used for the near-real-time listing APIs.
        timeout_s=600.0,
        interval_s=15.0,
    )
    total = sum(s.get("logGroupCount", 0) for s in aggregate)
    assert total == 1, (
        f"expected exactly one log group matching {token}, got {total}: {aggregate}"
    )

    query_id = logs.start_query(
        logGroupNames=[log_group_name],
        startTime=int(time.time()) - 3600,
        endTime=int(time.time()) + 60,
        queryString="fields @timestamp | limit 1",
    )["queryId"]
    ctx.on_cleanup(lambda: _best_effort_stop_query(logs, query_id))

    status = _poll_until(
        lambda: logs.get_query_results(queryId=query_id)["status"],
        lambda s: s in ("Complete", "Failed", "Cancelled", "Timeout"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert status == "Complete", f"unexpected query status: {status}"

    analyzed = logs.list_log_groups_for_query(queryId=query_id)["logGroupIdentifiers"]
    assert any(log_group_name in ident or ident == log_group_arn for ident in analyzed), (
        f"log group not reported by ListLogGroupsForQuery: {analyzed}"
    )

    logs.delete_log_group(logGroupName=log_group_name)
    after_delete = _poll_until(
        lambda: logs.describe_log_groups(logGroupNamePattern=token)["logGroups"],
        lambda groups: len(groups) == 0,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert not after_delete, (
        f"log group still visible in DescribeLogGroups after delete: {after_delete}"
    )


def _best_effort_delete_log_group(logs, log_group_name):
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _best_effort_stop_query(logs, query_id):
    try:
        logs.stop_query(queryId=query_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
