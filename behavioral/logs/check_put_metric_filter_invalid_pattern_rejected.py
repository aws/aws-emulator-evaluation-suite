"""put-metric-filter-invalid-pattern-rejected."""
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


CHECK = "put-metric-filter-invalid-pattern-rejected"
GROUP = 'metric-filters'
SERVICES = ['logs']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMetricFilter refuses a malformed filterPattern with InvalidParameterException and its exact
    message and creates no filter, while a well-formed pattern on the same group is created.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-mf-bad-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    # Positive control: the same call shape, a well-formed pattern.
    good_name = ctx.unique_name("sim2real-behav-mf-good-")
    svc.put_metric_filter(
        logGroupName=group,
        filterName=good_name,
        filterPattern="ERROR",
        metricTransformations=[
            {
                "metricName": "GoodControl",
                "metricNamespace": "sim2real/behavioral",
                "metricValue": "1",
            }
        ],
    )
    ctx.on_cleanup(lambda _n=group, _f=good_name: svc.delete_metric_filter(logGroupName=_n, filterName=_f))
    good_desc = svc.describe_metric_filters(logGroupName=group, filterNamePrefix=good_name)
    good_matches = good_desc.get("metricFilters", [])
    assert len(good_matches) == 1, f"the positive control did not create a retrievable filter: {good_matches!r}"
    assert good_matches[0]["filterPattern"] == "ERROR", (
        f"the positive control's stored pattern was {good_matches[0].get('filterPattern')!r}, expected 'ERROR'"
    )

    filter_name = ctx.unique_name("sim2real-behav-mf-bad-")
    code, message = _client_error(
        lambda: svc.put_metric_filter(
            logGroupName=group,
            filterName=filter_name,
            filterPattern="[ unterminated bracket",
            metricTransformations=[
                {
                    "metricName": "Bogus",
                    "metricNamespace": "sim2real/behavioral",
                    "metricValue": "1",
                }
            ],
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == "If a filter pattern starts with '[' it must end with ']'", (
        f"unexpected message: {message!r}"
    )

    desc = svc.describe_metric_filters(logGroupName=group, filterNamePrefix=filter_name)
    assert desc.get("metricFilters", []) == [], "malformed-pattern filter was created anyway"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
