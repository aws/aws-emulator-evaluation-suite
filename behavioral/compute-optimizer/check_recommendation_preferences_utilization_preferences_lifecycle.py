"""recommendation-preferences-utilization-preferences-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "recommendation-preferences-utilization-preferences-lifecycle"
GROUP = "state-machine"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """PutRecommendationPreferences with a custom CPU utilizationPreferences
    (threshold + headroom) round-trips through GetRecommendationPreferences and is
    fully removed by DeleteRecommendationPreferences.
    """
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    scope = {"name": "AccountId", "value": account_id}
    utilization_preferences = [
        {
            "metricName": "CpuUtilization",
            "metricParameters": {"headroom": "PERCENT_30", "threshold": "P90"},
        }
    ]

    co.put_recommendation_preferences(
        resourceType="Ec2Instance", scope=scope, utilizationPreferences=utilization_preferences
    )
    ctx.on_cleanup(
        lambda: co.delete_recommendation_preferences(
            resourceType="Ec2Instance", scope=scope, recommendationPreferenceNames=["UtilizationPreferences"]
        )
    )

    detail = _find_detail(co, "Ec2Instance", scope)
    assert detail is not None, f"expected an AccountId-scoped detail after Put, got none (scope={scope})"
    assert detail["utilizationPreferences"] == utilization_preferences, (
        f"expected utilizationPreferences={utilization_preferences}, "
        f"got {detail.get('utilizationPreferences')}"
    )

    co.delete_recommendation_preferences(
        resourceType="Ec2Instance", scope=scope, recommendationPreferenceNames=["UtilizationPreferences"]
    )

    detail_after = _find_detail(co, "Ec2Instance", scope)
    assert detail_after is None or not detail_after.get("utilizationPreferences"), (
        f"expected utilizationPreferences to be gone after Delete, got {detail_after}"
    )


def _find_detail(co, resource_type, scope):
    resp = co.get_recommendation_preferences(resourceType=resource_type, scope=scope)
    for detail in resp.get("recommendationPreferencesDetails", []):
        if detail.get("scope", {}).get("name") == scope["name"] and detail.get("scope", {}).get("value") == scope["value"]:
            return detail
    return None


def _ensure_opted_in(co, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    status = co.get_enrollment_status().get("status")
    if status != "Active":
        co.update_enrollment_status(status="Active")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = co.get_enrollment_status().get("status")
        if status == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"account never reached Active enrollment status, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
