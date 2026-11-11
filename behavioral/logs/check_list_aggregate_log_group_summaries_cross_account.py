"""list-aggregate-log-group-summaries-cross-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-aggregate-log-group-summaries-cross-account"
GROUP = "server-side"
SERVICES = ["logs"]

_COUNT = 3


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListAggregateLogGroupSummaries scoped by logGroupNamePattern returns server-aggregated rows, each
    with groupingIdentifiers and a positive logGroupCount, whose counts sum to the groups the check made.
    """
    import time

    logs = ctx.client("logs")
    prefix = ctx.unique_name("sim2real-behav-aggr-")
    created = []
    for i in range(_COUNT):
        name = f"{prefix}{i}"
        logs.create_log_group(logGroupName=name, tags={"sim2real-check": CHECK})
        ctx.on_cleanup(lambda n=name: logs.delete_log_group(logGroupName=n))
        # A log group with no log events is never surfaced by the server-side aggregation index
        # (it only indexes data sources that actually have indexed log data), so put at least one
        # event into each group -- otherwise ListAggregateLogGroupSummaries permanently reports
        # zero groups for it, no matter how long we poll.
        stream_name = "sim2real-probe-stream"
        logs.create_log_stream(logGroupName=name, logStreamName=stream_name)
        logs.put_log_events(
            logGroupName=name,
            logStreamName=stream_name,
            logEvents=[{"timestamp": int(time.time() * 1000), "message": "sim2real probe event"}],
        )
        created.append(name)

    def _fetch_summaries():
        summaries = []
        next_token = None
        while True:
            kwargs = {"groupBy": "DATA_SOURCE_NAME_AND_TYPE", "logGroupNamePattern": prefix}
            if next_token:
                kwargs["nextToken"] = next_token
            resp = logs.list_aggregate_log_group_summaries(**kwargs)
            summaries.extend(resp.get("aggregateLogGroupSummaries", []))
            next_token = resp.get("nextToken")
            if not next_token:
                break
        return summaries

    # The server-side aggregation index lags behind log group creation, and while it converges it
    # can transiently overshoot (duplicate/provisional groupKey entries before the index settles)
    # as well as undershoot (some groups not yet indexed). Stopping as soon as the running total
    # is *at least* _COUNT is therefore unsafe -- a transient overshoot past _COUNT would make the
    # poll stop early on a value that never actually settles back to _COUNT. Poll (bounded, with a
    # generous timeout to accommodate real-world indexing latency) until the total exactly matches
    # the number of log groups we created.
    summaries = _poll_until(
        _fetch_summaries,
        lambda s: sum(x.get("logGroupCount", 0) for x in s) == _COUNT,
        timeout=240,
        interval=5.0,
    )

    # The response is a list of {groupingIdentifiers, logGroupCount} aggregates, never
    # per-log-group rows. (The actual API field is "groupingIdentifiers", an array of key-value
    # pairs identifying the data-source characteristics used to group the log groups -- not a
    # single "groupKey" field.)
    for summary in summaries:
        assert "logGroupCount" in summary and "groupingIdentifiers" in summary, summary
        assert isinstance(summary["logGroupCount"], int) and summary["logGroupCount"] > 0, summary

    total = sum(s["logGroupCount"] for s in summaries)
    assert total == _COUNT, (
        f"expected the {_COUNT} log groups scoped by logGroupNamePattern={prefix!r} to be fully "
        f"accounted for by the server-side aggregation, got total={total} across {summaries}"
    )


def _poll_until(fn, predicate, timeout=30, interval=1.0):
    import time

    deadline = time.monotonic() + timeout
    result = fn()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout}s (last={result!r})")
        time.sleep(interval)
        result = fn()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
