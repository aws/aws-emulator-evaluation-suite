"""recommendation-preferences-preferred-resources-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "recommendation-preferences-preferred-resources-lifecycle"
GROUP = "state-machine"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """A preferredResources excludeList of ["m6g.large"] reads back with m6g.large absent from
    effectiveIncludeList and m6g.medium still present, and DeleteRecommendationPreferences removes it."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    scope = {"name": "AccountId", "value": account_id}
    preferred_resources = [{"name": "Ec2InstanceTypes", "excludeList": ["m6g.large"]}]

    # The account-scoped preference is a per-account singleton: snapshot it and restore it.
    prior = (_find_detail(co, "Ec2Instance", scope) or {}).get("preferredResources") or []
    prior_put = [
        {k: e[k] for k in ("name", "includeList", "excludeList") if e.get(k)} for e in prior
    ]

    co.put_recommendation_preferences(
        resourceType="Ec2Instance", scope=scope, preferredResources=preferred_resources
    )

    def _restore():
        co.delete_recommendation_preferences(
            resourceType="Ec2Instance", scope=scope, recommendationPreferenceNames=["PreferredResources"]
        )
        if prior_put:
            co.put_recommendation_preferences(
                resourceType="Ec2Instance", scope=scope, preferredResources=prior_put
            )

    ctx.on_cleanup(_restore)

    detail = _find_detail(co, "Ec2Instance", scope)
    assert detail is not None
    assert detail["preferredResources"], "expected a resolved preferredResources entry"
    entry = detail["preferredResources"][0]
    assert entry["excludeList"] == ["m6g.large"], f"expected excludeList=['m6g.large'], got {entry.get('excludeList')!r}"
    assert "effectiveIncludeList" in entry, f"expected a resolved effectiveIncludeList, got entry={entry!r}"
    effective = entry["effectiveIncludeList"]
    assert effective, "expected a non-empty effective candidate list expanding the wildcard defaults"
    assert "m6g.large" not in effective, f"expected m6g.large excluded (n={len(effective)})"
    assert "m6g.medium" in effective, f"expected a sibling size still a candidate (n={len(effective)})"

    co.delete_recommendation_preferences(
        resourceType="Ec2Instance", scope=scope, recommendationPreferenceNames=["PreferredResources"]
    )

    detail_after = _find_detail(co, "Ec2Instance", scope)
    assert detail_after is None or not detail_after.get("preferredResources")


def _find_detail(co, resource_type, scope):
    resp = co.get_recommendation_preferences(resourceType=resource_type, scope=scope)
    for detail in resp.get("recommendationPreferencesDetails", []):
        if detail.get("scope", {}).get("name") == scope["name"] and detail.get("scope", {}).get("value") == scope["value"]:
            return detail
    return None


def _ensure_opted_in(co, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    """Opt the account in as a precondition, and leave it opted in.

    Enrollment is deliberately not restored: after an opt-out AWS refuses an opt-in for 24
    hours ("Cannot opt-in within 24 hours of opt-out"), so a restore would fail every later
    check in the account for a day.
    """
    status = co.get_enrollment_status()["status"]
    if status == "Active":
        return
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
