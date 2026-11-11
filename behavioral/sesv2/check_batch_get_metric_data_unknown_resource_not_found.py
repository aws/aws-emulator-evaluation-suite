"""batch-get-metric-data-unknown-resource-not-found."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "batch-get-metric-data-unknown-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c2", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """BatchGetMetricData on an unknown configuration set succeeds with an empty or all-zero series.

    No per-query Errors entry is returned and exactly one q1 result is present; the same query
    against a real configuration set also succeeds with a q1 result and no Errors.
    """
    ses = ctx.client("sesv2")
    _ensure_vdm_enabled(ctx, ses)
    # BatchGetMetricData requires a full-day (midnight-to-midnight UTC) interval for
    # this metric shape -- "partial-day" ranges are rejected with BadRequestException,
    # so align the window to day boundaries to isolate the resource-existence behavior
    # under test from that unrelated validation rule.
    today_midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    end = today_midnight
    start = end - timedelta(days=1)

    missing_config_set = ctx.unique_name("sim2real-missing-cs-")
    unknown_result = ses.batch_get_metric_data(
        Queries=[
            {
                "Id": "q1",
                "Namespace": "VDM",
                "Metric": "SEND",
                "StartDate": start,
                "EndDate": end,
                "Dimensions": {"CONFIGURATION_SET": missing_config_set},
            }
        ]
    )
    # No error at all -- neither a raised exception nor a per-query MetricDataError.
    assert not unknown_result.get("Errors"), (
        f"unknown configuration set produced a per-query error: {unknown_result.get('Errors')}"
    )
    unknown_rows = [r for r in unknown_result.get("Results", []) if r["Id"] == "q1"]
    assert len(unknown_rows) == 1, f"expected exactly one Results entry for q1, got {unknown_rows}"
    unknown_values = unknown_rows[0].get("Values", [])
    assert unknown_values == [] or all(v == 0 for v in unknown_values), (
        f"unknown configuration set's metric series was neither empty nor all-zero: {unknown_values}"
    )

    # positive control: the same query shape against a real configuration set succeeds
    # with the identical empty-series shape (proving the behavior above isn't a fluke).
    real_config_set = ctx.unique_name("sim2real-cs-")
    ses.create_configuration_set(ConfigurationSetName=real_config_set)
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=real_config_set))

    result = ses.batch_get_metric_data(
        Queries=[
            {
                "Id": "q1",
                "Namespace": "VDM",
                "Metric": "SEND",
                "StartDate": start,
                "EndDate": end,
                "Dimensions": {"CONFIGURATION_SET": real_config_set},
            }
        ]
    )
    assert not result.get("Errors"), f"real configuration set produced a per-query error: {result.get('Errors')}"
    assert any(r["Id"] == "q1" for r in result.get("Results", [])), (
        "real configuration set's query produced no Results entry for q1"
    )


def _ensure_vdm_enabled(ctx, sesv2) -> None:
    """BatchGetMetricData 404s account-wide with NotFoundException unless Virtual Deliverability
    Manager is enabled; enable it, restoring the account's prior VDM attributes in teardown."""
    current = sesv2.get_account().get("VdmAttributes", {})
    if current.get("VdmEnabled") != "ENABLED":
        original = {**current, "VdmEnabled": current.get("VdmEnabled", "DISABLED")}
        ctx.on_cleanup(lambda: sesv2.put_account_vdm_attributes(VdmAttributes=original))
        sesv2.put_account_vdm_attributes(
            VdmAttributes={
                "VdmEnabled": "ENABLED",
                "DashboardAttributes": {"EngagementMetrics": "DISABLED"},
                "GuardianAttributes": {"OptimizedSharedDelivery": "DISABLED"},
            }
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
