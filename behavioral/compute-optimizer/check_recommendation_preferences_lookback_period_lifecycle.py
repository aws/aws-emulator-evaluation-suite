"""recommendation-preferences-lookback-period-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "recommendation-preferences-lookback-period-lifecycle"
GROUP = "state-machine"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """An account-level lookBackPeriod DAYS_32 put with PutRecommendationPreferences reads back as DAYS_32,
    and after DeleteRecommendationPreferences no account-level lookBackPeriod is returned."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    scope = {"name": "AccountId", "value": account_id}

    co.put_recommendation_preferences(
        resourceType="Ec2Instance", scope=scope, lookBackPeriod="DAYS_32"
    )
    ctx.on_cleanup(
        lambda: co.delete_recommendation_preferences(
            resourceType="Ec2Instance", scope=scope, recommendationPreferenceNames=["LookBackPeriodPreference"]
        )
    )

    detail = _find_detail(co, "Ec2Instance", scope)
    assert detail is not None, f"expected an AccountId-scoped detail after Put, found none in {scope}"
    assert detail["lookBackPeriod"] == "DAYS_32", (
        f"expected lookBackPeriod=DAYS_32 after Put, got {detail['lookBackPeriod']!r}"
    )

    co.delete_recommendation_preferences(
        resourceType="Ec2Instance", scope=scope, recommendationPreferenceNames=["LookBackPeriodPreference"]
    )

    detail_after = _find_detail(co, "Ec2Instance", scope)
    assert detail_after is None or detail_after.get("lookBackPeriod") is None, (
        f"expected lookBackPeriod to be absent after Delete, got {detail_after}"
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
