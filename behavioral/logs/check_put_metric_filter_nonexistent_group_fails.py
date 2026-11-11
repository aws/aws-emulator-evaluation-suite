"""put-metric-filter-nonexistent-group-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

CHECK = "put-metric-filter-nonexistent-group-fails"
GROUP = 'metric-filters'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMetricFilter against a nonexistent log group is rejected with ResourceNotFoundException
    and creates nothing, while the identical call against a real log group in the same run
    succeeds (positive control)."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-metric-missing-")
    bogus_group = ctx.unique_name("sim2real-behav-lg-metric-missing-bogus-")
    filter_name = ctx.unique_name("sim2real-behav-filter-")
    namespace = ctx.unique_name("Sim2RealMetricMissing")

    def _put(log_group_name):
        return svc.put_metric_filter(
            logGroupName=log_group_name,
            filterName=filter_name,
            filterPattern="ERROR",
            metricTransformations=[
                {
                    "metricName": "ErrorCount",
                    "metricNamespace": namespace,
                    "metricValue": "1",
                }
            ],
        )

    # Break exactly one thing: target a log group name that was never created.
    code, message = _client_error(lambda: _put(bogus_group))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "The specified log group does not exist.", f"unexpected message: {message!r}"

    # Effect absent, via an independent read: the bogus group has no filters -- and an
    # independent operation against it is refused the same way, so nothing was persisted.
    describe_code, describe_message = _client_error(lambda: svc.describe_metric_filters(logGroupName=bogus_group))
    assert describe_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {describe_code}"
    )
    assert describe_message == "The specified log group does not exist.", f"unexpected message: {describe_message!r}"

    # Positive control: the identical call succeeds against a log group that does exist.
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))
    _put(group)
    ctx.on_cleanup(lambda: svc.delete_metric_filter(logGroupName=group, filterName=filter_name))

    # Terminal read is independent of the mutating call, at the destination.
    listed = svc.describe_metric_filters(logGroupName=group, filterNamePrefix=filter_name)[
        "metricFilters"
    ]
    assert [f["filterName"] for f in listed] == [filter_name], f"expected filter to exist, got {listed}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
