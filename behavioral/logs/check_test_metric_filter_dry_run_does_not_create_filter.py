"""test-metric-filter-dry-run-does-not-create-filter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "test-metric-filter-dry-run-does-not-create-filter"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestMetricFilter evaluates a filter pattern against sample lines without persisting
    a metric filter, so DescribeMetricFilters must remain unchanged afterward."""
    logs = ctx.client("logs")
    log_group = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    # baseline: no metric filters exist on this fresh log group
    before = logs.describe_metric_filters(logGroupName=log_group)["metricFilters"]
    assert before == [], f"expected no filters before test, got {before}"

    filter_name = ctx.unique_name("sim2real-behav-mf-")
    sample_messages = [
        "02 May 2014 00:34:12,525 [INFO] Starting the application",
        "02 May 2014 00:34:16,142 [ERROR] Unhandled exception: InvalidQueryException",
        "02 May 2014 00:34:16,224 [ERROR] Terminating the application",
        "02 May 2014 00:35:14,245 [DEBUG] Database connection established",
    ]
    result = logs.test_metric_filter(
        filterPattern='"[ERROR]"',
        logEventMessages=sample_messages,
    )
    matches = result["matches"]
    matched_messages = {m["eventMessage"] for m in matches}
    # TestMetricFilter must actually evaluate the pattern (it's not a no-op stub)
    assert len(matches) == 2, f"expected 2 [ERROR] matches, got {matches}"
    assert all("[ERROR]" in msg for msg in matched_messages), (
        f"every match must actually contain the [ERROR] pattern, got {matched_messages}"
    )

    # crucially: TestMetricFilter is a dry run — it must NOT persist anything
    after = logs.describe_metric_filters(logGroupName=log_group)["metricFilters"]
    assert after == [], f"TestMetricFilter unexpectedly created a persisted filter: {after}"

    # and specifically, no filter carrying our generated name exists anywhere in the account
    prefix_matches = logs.describe_metric_filters(
        logGroupName=log_group, filterNamePrefix=filter_name[:20]
    ).get("metricFilters", [])
    assert prefix_matches == [], (
        f"no filter named {filter_name!r} should exist, but found {prefix_matches}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
