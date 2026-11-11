"""custom-detection-rule-org-configuration-lifecycle."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-detection-rule-org-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """Get/Update/DeleteCustomDetectionRuleOrgConfiguration each reject a RuleId with no org
    configuration rather than succeeding or fabricating a result, and
    ListCustomDetectionRuleOrgConfigurations never lists that RuleId."""
    gd = ctx.client("guardduty")
    _get_or_create_detector(ctx)  # list operations 400 with "no detector" if the account has none
    bogus_rule_id = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
    mode = "DRY_RUN"
    # RuleId non-existence, caller-authorization (not the delegated
    # GuardDuty organization admin), and malformed-RuleId-format are all
    # legitimate reasons for GuardDuty to reject these calls from an isolated
    # test account; whichever boundary fires, it proves the same thing -- no
    # org configuration is fabricated or mutated for a RuleId/caller that was
    # never provisioned/authorized.
    acceptable = {"ResourceNotFoundException", "AccessDeniedException", "BadRequestException"}
    # The exact wording AWS returns for the authorization boundary an isolated caller meets.
    worded = {
        "AccessDeniedException": "The request is rejected because the caller is not authorized to call this API.",
    }

    def _graded(op: str, code: str, message: str) -> None:
        assert code in acceptable, f"{op}: expected one of {acceptable}, got {code!r}"
        if code in worded:
            assert message == worded[code], f"{op}: expected message {worded[code]!r}, got {message!r}"

    _graded("GetCustomDetectionRuleOrgConfiguration", *_error_code(
        lambda: gd.get_custom_detection_rule_org_configuration(RuleId=bogus_rule_id, Mode=mode)
    ))
    _graded("UpdateCustomDetectionRuleOrgConfiguration", *_error_code(
        lambda: gd.update_custom_detection_rule_org_configuration(RuleId=bogus_rule_id, Mode=mode)
    ))
    _graded("DeleteCustomDetectionRuleOrgConfiguration", *_error_code(
        lambda: gd.delete_custom_detection_rule_org_configuration(RuleId=bogus_rule_id, Mode=mode)
    ))

    # An isolated (non-delegated-admin) caller may also be denied on List
    # itself; that is an acceptable manifestation of the same authorization
    # boundary already exercised above.
    try:
        listing = gd.list_custom_detection_rule_org_configurations()
    except ClientError as err:
        _graded("ListCustomDetectionRuleOrgConfigurations", err.response["Error"]["Code"],
                err.response["Error"].get("Message", ""))
    else:
        configs = listing.get("Configurations", [])
        assert isinstance(configs, list), f"expected Configurations to be a list, got {type(configs).__name__}"
        assert not any(c.get("RuleId") == bogus_rule_id for c in configs), (
            f"bogus RuleId {bogus_rule_id!r} must never appear in ListCustomDetectionRuleOrgConfigurations"
        )


# ===== helpers =====

def _error_code(fn) -> Any:
    """Call fn(); return its (code, message). An unexpected SUCCESS raises: a target that answers
    a never-provisioned RuleId must not be reduced to a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _get_or_create_detector(ctx) -> str:
    gd = ctx.client("guardduty")
    ids = gd.list_detectors().get("DetectorIds", [])
    if ids:
        return ids[0]
    detector_id = gd.create_detector(Enable=True)["DetectorId"]

    def _cleanup():
        try:
            gd.delete_detector(DetectorId=detector_id)
        except ClientError as err:
            # GuardDuty reports a detector that is already gone as BadRequestException.
            if err.response["Error"]["Code"] != "BadRequestException":
                raise

    ctx.on_cleanup(_cleanup)
    return detector_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
