"""put-metric-filter-then-describe."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-metric-filter-then-describe"
GROUP = 'metric-filters'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetricFilter makes the filter visible via DescribeMetricFilters."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-metric-")
    filter_name = ctx.unique_name("sim2real-behav-filter-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    svc.put_metric_filter(
        logGroupName=group,
        filterName=filter_name,
        filterPattern="ERROR",
        metricTransformations=[
            {
                "metricName": "ErrorCount",
                "metricNamespace": "BehavioralChecks",
                "metricValue": "1",
            }
        ],
    )

    resp = svc.describe_metric_filters(logGroupName=group, filterNamePrefix=filter_name)
    matches = [f for f in resp.get("metricFilters", []) if f["filterName"] == filter_name]
    assert len(matches) == 1, f"expected exactly one filter named {filter_name}, got {resp.get('metricFilters')}"
    mf = matches[0]
    assert mf["filterPattern"] == "ERROR", f"expected filterPattern 'ERROR', got {mf.get('filterPattern')!r}"
    transform = mf["metricTransformations"][0]
    assert transform["metricName"] == "ErrorCount", f"expected metricName 'ErrorCount', got {transform.get('metricName')!r}"
    assert transform["metricNamespace"] == "BehavioralChecks", (
        f"expected metricNamespace 'BehavioralChecks', got {transform.get('metricNamespace')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
