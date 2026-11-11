"""put-recommendation-preferences-concurrent-writes-consistent."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "put-recommendation-preferences-concurrent-writes-consistent"
GROUP = "concurrency"
SERVICES = ["compute-optimizer"]

# LookBackPeriodPreference has exactly three modelled values (DAYS_14/32/93), and DAYS_14 is the
# service's own fallback default. The race deliberately excludes it: a target that no-ops on Put and
# always reports the default would otherwise satisfy "result is one of the raced values" by
# accident. DAYS_93 is written and verified as a single-writer baseline *before* the race, then
# excluded from the race set, so the final read can only be unchanged (defect: race did not apply)
# or corrupted (defect: not a valid raced value) or correct (one of the two raced values, and
# different from the baseline).
_BASELINE_VALUE = "DAYS_93"
_RACE_VALUES = ["DAYS_14", "DAYS_32", "DAYS_14", "DAYS_32", "DAYS_14", "DAYS_32"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """Concurrent PutRecommendationPreferences of DAYS_14 and DAYS_32 over a DAYS_93 baseline leave the
    account-level lookBackPeriod at one of the raced values, never the baseline or a missing value."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    scope = {"name": "AccountId", "value": account_id}
    ctx.on_cleanup(
        lambda: co.delete_recommendation_preferences(
            resourceType="Ec2Instance", scope=scope, recommendationPreferenceNames=["LookBackPeriodPreference"]
        )
    )

    def _write(value: str) -> None:
        co.put_recommendation_preferences(resourceType="Ec2Instance", scope=scope, lookBackPeriod=value)

    _write(_BASELINE_VALUE)
    baseline = _find_detail(co, "Ec2Instance", scope)
    assert baseline is not None, "expected a preference detail after the baseline PutRecommendationPreferences"
    assert baseline["lookBackPeriod"] == _BASELINE_VALUE, (
        f"expected baseline lookBackPeriod={_BASELINE_VALUE!r}, got {baseline.get('lookBackPeriod')!r}"
    )

    with ThreadPoolExecutor(max_workers=len(_RACE_VALUES)) as pool:
        futures = [pool.submit(_write, value) for value in _RACE_VALUES]
        for future in futures:
            future.result()

    detail = _find_detail(co, "Ec2Instance", scope)
    assert detail is not None, "expected a preference detail after concurrent PutRecommendationPreferences"
    result = detail.get("lookBackPeriod")
    assert result in set(_RACE_VALUES), (
        f"expected lookBackPeriod to be one of the raced values {sorted(set(_RACE_VALUES))}, "
        f"got {result!r} (corrupted/partial concurrent write)"
    )
    assert result != _BASELINE_VALUE, (
        f"lookBackPeriod is still the pre-race baseline {_BASELINE_VALUE!r} after concurrent writes — "
        "no racer's write took effect"
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
