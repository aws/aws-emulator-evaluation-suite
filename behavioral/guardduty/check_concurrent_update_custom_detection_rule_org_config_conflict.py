"""concurrent-update-custom-detection-rule-org-config-conflict."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-custom-detection-rule-org-config-conflict"
GROUP = "concurrency"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """Without delegated administrator rights, five concurrent
    UpdateCustomDetectionRuleOrgConfiguration calls all raise AccessDeniedException with the
    exact message, and DescribeOrganizationConfiguration raises BadRequestException.
    """
    gd = ctx.client("guardduty")
    _ensure_detector(ctx, gd)

    # positive control: the custom-detection-rule surface is reachable and
    # populated -- AWS ships managed rules and this call is NOT admin-gated,
    # so a denial below can't be explained by "everything is denied".
    rules = gd.list_custom_detection_rules().get("Rules", [])
    assert rules, "list_custom_detection_rules returned no rules -- cannot pick a RuleId to probe"
    rule_id = rules[0]["RuleId"]
    mode = "DRY_RUN"

    def _racer(_):
        try:
            gd.update_custom_detection_rule_org_configuration(
                RuleId=rule_id, Mode=mode, IncludeAccountIds=["999999999000"]
            )
            return ("ok", None, None)
        except ClientError as exc:
            return ("err", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=5) as pool:
        outcomes = list(pool.map(_racer, range(5)))

    for kind, code, message in outcomes:
        assert kind == "err" and code == "AccessDeniedException", (
            "expected every concurrent UpdateCustomDetectionRuleOrgConfiguration racer "
            f"to be denied for this non-delegated-admin caller, got kind={kind} code={code}"
        )
        expected_message = "The request is rejected because the caller is not authorized to call this API."
        assert message == expected_message, (
            f"expected AccessDeniedException message {expected_message!r}, got {message!r}"
        )

    # independent read, a different operation than the one just probed: the
    # account-level org-admin status GuardDuty itself reports corroborates
    # *why* -- distinguishing "not eligible" from a malformed request or a
    # caller with no permissions at all.
    detector_id = _ensure_detector(ctx, gd)
    code, message = _expect_denied(
        lambda: gd.describe_organization_configuration(DetectorId=detector_id),
        "describe_organization_configuration succeeded -- this account may have become "
        "the GuardDuty delegated admin; the concurrent-update race this check exists to "
        "test is now reachable and should be exercised directly instead of asserting the "
        "org-admin-gate withdrawal",
    )
    assert code == "BadRequestException", code
    expected_message = "The request failed because a delegated administrator account has not been enabled."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _ensure_detector(ctx, gd):
    """GuardDuty's account-level APIs (including the custom-detection-rule
    family) require an enabled detector to exist in this account/region.
    Reuse one if present; otherwise create one and tear it down on cleanup
    so the check leaves no lasting account-level state behind."""
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0]
    tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    detector_id = gd.create_detector(Enable=True, Tags=tags)["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id


def _expect_denied(fn, unexpected_success_detail: str) -> tuple[str, Any]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(unexpected_success_detail)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
