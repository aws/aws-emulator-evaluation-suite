"""batch-get-metric-data-invalid-metric-namespace-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-metric-data-invalid-metric-namespace-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:ses-account")
def run(ctx) -> None:
    """BatchGetMetricData rejects a Namespace outside the VDM-only enum with BadRequestException,
    while a well-formed query succeeds before and after the rejected call."""
    sesv2 = ctx.client("sesv2")
    unvalidated_sesv2 = ctx.client("sesv2", config=Config(parameter_validation=False))
    _ensure_vdm_enabled(ctx, sesv2)

    cfg_set_name = ctx.unique_name("sim2real-metrics-cs-")
    sesv2.create_configuration_set(ConfigurationSetName=cfg_set_name)
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=cfg_set_name))

    # Daily-aggregated VDM queries require day-aligned (midnight UTC) boundaries.
    today_midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    start = today_midnight - timedelta(days=3)
    end = today_midnight

    def _valid_query():
        return sesv2.batch_get_metric_data(
            Queries=[
                {
                    "Id": "ok",
                    "Namespace": "VDM",
                    "Metric": "SEND",
                    "StartDate": start,
                    "EndDate": end,
                    "Dimensions": {"CONFIGURATION_SET": cfg_set_name},
                }
            ]
        )

    before = _valid_query()
    assert "ok" in {r["Id"] for r in before.get("Results", [])}, (
        f"positive control: expected 'ok' in Results before the rejected call, got {before!r}"
    )
    assert "ok" not in {e["Id"] for e in before.get("Errors", [])}, (
        f"positive control: expected no error for 'ok' before the rejected call, got {before!r}"
    )

    def _invalid_call():
        return unvalidated_sesv2.batch_get_metric_data(
            Queries=[
                {
                    "Id": "bad",
                    # botocore enforces this enum client-side; the client above disables
                    # parameter validation so the server's own rejection is exercised.
                    "Namespace": "NOT-A-REAL-NAMESPACE",
                    "Metric": "SEND",
                    "StartDate": start,
                    "EndDate": end,
                    "Dimensions": {"CONFIGURATION_SET": cfg_set_name},
                }
            ]
        )

    err = _error(_invalid_call)
    expected = (
        "BadRequestException",
        "1 validation error detected: Value at 'queries.1.member.namespace' failed to satisfy "
        "constraint: Member must satisfy enum value set: [VDM]",
    )
    assert err == expected, f"expected {expected!r}, got {err!r}"

    after = _valid_query()
    assert "ok" in {r["Id"] for r in after.get("Results", [])}, (
        "positive control stopped succeeding after the rejected call"
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


def _error(fn) -> tuple:
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return (err.response["Error"]["Code"], err.response["Error"].get("Message"))
    raise AssertionError(
        f"expected BatchGetMetricData to reject the invalid namespace, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
