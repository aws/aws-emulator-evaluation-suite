"""delete-org-config-conflict-when-associations-exist."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-org-config-conflict-when-associations-exist"
GROUP = "error-semantics"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """For a caller that is not the GuardDuty delegated administrator, creating an org configuration
    for a catalog-listed custom detection rule and listing org configurations both fail with
    AccessDeniedException and its exact message, while ListCustomDetectionRules succeeds."""
    gd = ctx.client("guardduty")
    _ensure_detector(ctx, gd)

    # Positive control: the account-agnostic catalog read succeeds, so a denial below is
    # the delegated-admin boundary, not a broken account/credential.
    rules = gd.list_custom_detection_rules().get("Rules", [])
    assert rules, "expected at least one AWS-managed custom detection rule in the catalog"
    rule_id = rules[0]["RuleId"]

    create_code, create_message = _error_code(
        lambda: gd.create_custom_detection_rule_org_configuration(RuleId=rule_id, Mode="DRY_RUN")
    )
    assert create_code == "AccessDeniedException", (
        "expected CreateCustomDetectionRuleOrgConfiguration to deny a non-delegated-admin "
        f"caller even for a real, catalog-listed RuleId, got {create_code!r}"
    )
    assert create_message == _DENIED_MESSAGE, (
        f"expected message {_DENIED_MESSAGE!r}, got {create_message!r}"
    )

    # Effect absent: nothing was created, and the org-configuration list surface for the
    # family answers with the same denial rather than showing a stray configuration.
    list_configs_code, list_message = _error_code(
        lambda: gd.list_custom_detection_rule_org_configurations()
    )
    assert list_configs_code == "AccessDeniedException", (
        "expected ListCustomDetectionRuleOrgConfigurations to deny a non-delegated-admin "
        f"caller too, got {list_configs_code!r}"
    )
    assert list_message == _DENIED_MESSAGE, f"expected message {_DENIED_MESSAGE!r}, got {list_message!r}"


def _ensure_detector(ctx, gd):
    """GuardDuty's account-level APIs (including the custom-detection-rule
    family) require an enabled detector to exist in this account/region.
    Reuse one if present; otherwise create one and tear it down on cleanup
    so the check leaves no lasting account-level state behind."""
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0]
    detector_id = gd.create_detector(Enable=True, Tags={"sim2real-check": CHECK})["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id


_DENIED_MESSAGE = "The request is rejected because the caller is not authorized to call this API."


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected AccessDeniedException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
