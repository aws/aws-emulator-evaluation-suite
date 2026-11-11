"""list-automation-rule-preview-structure."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-automation-rule-preview-structure"
GROUP = "state"
SERVICES = ["compute-optimizer-automation"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available and must not
    turn into an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """ListAutomationRulePreview returns well-typed preview results for a given rule-type/action
    combination, and its totals stay consistent with ListAutomationRulePreviewSummaries even when
    the account has nothing to recommend yet."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    # Positive control: the account and credentials are healthy for this operation before the
    # negative below tries to break it.
    resp = client.list_automation_rule_preview(
        ruleType="AccountRule",
        recommendedActionTypes=["SnapshotAndDeleteUnattachedEbsVolume"],
        maxResults=100,
    )
    results = resp["previewResults"]
    assert isinstance(results, list)
    for item in results:
        assert item["recommendedActionType"] == "SnapshotAndDeleteUnattachedEbsVolume"
        assert isinstance(item["recommendedActionId"], str) and len(item["recommendedActionId"]) == 16

    summaries = client.list_automation_rule_preview_summaries(
        ruleType="AccountRule",
        recommendedActionTypes=["SnapshotAndDeleteUnattachedEbsVolume"],
        maxResults=100,
    )
    summary_list = summaries["previewResultSummaries"]
    # Real AWS always returns an account-wide aggregate row for the filter, even with zero
    # matching actions (for example, an account with no snapshot-eligible EBS
    # volumes still returns [{"key": "ALL_Recommended_Action_Summary", "total":
    # {"recommendedActionCount": 0, ...}}]). A stub that answers both lists with [] must not
    # pass, so the terminal assertion requires the aggregate row rather than just typing an
    # empty list.
    assert isinstance(summary_list, list) and summary_list, (
        f"previewResultSummaries is {summary_list!r}, want at least the account-wide aggregate row"
    )
    aggregate_rows = [e for e in summary_list if e["key"] == "ALL_Recommended_Action_Summary"]
    assert len(aggregate_rows) == 1, (
        f"expected exactly one ALL_Recommended_Action_Summary row, got keys "
        f"{[e['key'] for e in summary_list]!r}"
    )
    for entry in summary_list:
        assert isinstance(entry["key"], str) and entry["key"]
        assert entry["total"]["recommendedActionCount"] >= 0

    # The two paginated views of the same filter must agree on totals — this holds (0 == 0) even
    # on an account with no qualifying resources yet, and it fails a target whose summaries and
    # preview list disagree. Only sound when neither response was truncated.
    if not resp.get("nextToken") and not summaries.get("nextToken"):
        summed = sum(entry["total"]["recommendedActionCount"] for entry in summary_list)
        assert summed == len(results), (
            f"summed recommendedActionCount {summed} across {len(summary_list)} summary "
            f"entries != {len(results)} previewResults for the identical filter"
        )

    # An unrecognized recommendedActionTypes value is invalid input on every account regardless of
    # data — this fires whether or not the account has any real recommendations to preview.
    error = _client_error(lambda: client.list_automation_rule_preview(
        ruleType="AccountRule",
        recommendedActionTypes=["NotARealActionType"],
        maxResults=10,
    ))
    assert error.get("Code") == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for an unrecognized recommendedActionTypes "
        f"value, got {error!r}"
    )
    expected_message = (
        "Invalid RecommendedActionType value: NotARealActionType. Valid values: "
        "SnapshotAndDeleteUnattachedEbsVolume, UpgradeEbsVolumeType"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


# ===== self-contained plumbing =====
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
