"""list-recommended-actions-and-summaries-structure."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-recommended-actions-and-summaries-structure"
GROUP = "state"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """ListRecommendedActions and ListRecommendedActionSummaries return well-typed, mutually-consistent data."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    actions_resp = client.list_recommended_actions(maxResults=25)
    actions = actions_resp["recommendedActions"]
    assert isinstance(actions, list), f"recommendedActions is {type(actions).__name__}, want list"
    valid_action_types = {"SnapshotAndDeleteUnattachedEbsVolume", "UpgradeEbsVolumeType"}
    for action in actions:
        assert action["recommendedActionType"] in valid_action_types, (
            f"recommendedActionType {action['recommendedActionType']!r} not in {valid_action_types}"
        )
        assert isinstance(action["recommendedActionId"], str) and len(action["recommendedActionId"]) == 16, (
            f"recommendedActionId {action.get('recommendedActionId')!r} is not a 16-char string"
        )
        assert action["resourceType"] == "EbsVolume", f"resourceType {action['resourceType']!r} != EbsVolume"

    summaries = client.list_recommended_action_summaries(maxResults=25)["recommendedActionSummaries"]
    # AWS returns an account-wide aggregate row even with zero recommended actions, e.g.
    # [{"key": "ALL_Recommended_Action_Summary", "total": {"recommendedActionCount": 0, ...}}];
    # the last assertion ties the two independent reads together, so two empty lists do not pass.
    assert isinstance(summaries, list) and summaries, (
        f"recommendedActionSummaries is {summaries!r}, want at least the account-wide aggregate row"
    )
    aggregate_rows = [s for s in summaries if s["key"] == "ALL_Recommended_Action_Summary"]
    assert len(aggregate_rows) == 1, (
        f"expected exactly one ALL_Recommended_Action_Summary row, got keys "
        f"{[s['key'] for s in summaries]!r}"
    )
    aggregate_count = aggregate_rows[0]["total"]["recommendedActionCount"]
    assert isinstance(aggregate_count, int) and aggregate_count >= 0, (
        f"ALL_Recommended_Action_Summary.total.recommendedActionCount is {aggregate_count!r}, "
        "want a non-negative int"
    )
    if "nextToken" not in actions_resp:
        assert aggregate_count == len(actions), (
            f"ALL_Recommended_Action_Summary.total.recommendedActionCount={aggregate_count} but "
            f"ListRecommendedActions returned {len(actions)} action(s) on an unpaginated listing"
        )


def _ensure_enrolled(ctx) -> None:
    

    co = ctx.client("compute-optimizer")
    base_status = co.get_enrollment_status().get("status")
    if base_status != "Active":
        co.update_enrollment_status(status="Active", includeMemberAccounts=False)
        deadline0 = time.monotonic() + 120
        while time.monotonic() < deadline0:
            base_status = co.get_enrollment_status().get("status")
            if base_status == "Active":
                break
            if base_status == "Failed":
                raise AssertionError("compute-optimizer base enrollment failed")
            time.sleep(3)
        else:
            raise AssertionError(
                "compute-optimizer base enrollment did not reach Active within 120s",
            )

    client = ctx.client("compute-optimizer-automation")
    cfg = client.get_enrollment_configuration()
    if cfg["status"] == "Active":
        return
    if cfg["status"] in ("Inactive", "Pending", "Failed"):
        client.update_enrollment_configuration(status="Active")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        cfg = client.get_enrollment_configuration()
        if cfg["status"] == "Active":
            return
        if cfg["status"] == "Failed":
            raise AssertionError(f"account enrollment failed: {cfg.get('statusReason')}")
        time.sleep(2)
    raise AssertionError(
        "account did not reach Active Compute Optimizer Automation enrollment status "
        "within 60s of requesting UpdateEnrollmentConfiguration(status=Active)",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
