"""delete-metric-filter-removes-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-metric-filter-removes-resource"
GROUP = 'metric-filters'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteMetricFilter removes the filter from DescribeMetricFilters."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-metric-del-")
    filter_name = ctx.unique_name("sim2real-behav-filter-")
    svc.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
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

    # Positive control: the filter must actually be listed before we exercise the delete,
    # otherwise a target whose DescribeMetricFilters always answers empty would pass below
    # without ever having created (or removed) anything.
    before = svc.describe_metric_filters(logGroupName=group, filterNamePrefix=filter_name)
    before_names = [f["filterName"] for f in before.get("metricFilters", [])]
    assert filter_name in before_names, (
        f"filter {filter_name} not listed after PutMetricFilter, got {before_names}"
    )

    svc.delete_metric_filter(logGroupName=group, filterName=filter_name)

    resp = svc.describe_metric_filters(logGroupName=group, filterNamePrefix=filter_name)
    names = [f["filterName"] for f in resp.get("metricFilters", [])]
    assert filter_name not in names, f"filter {filter_name} still present after delete"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
