"""delete-custom-detection-rule-org-configuration-conflict-when-associations-exist."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-custom-detection-rule-org-configuration-conflict-when-associations-exist"
GROUP = "concurrency"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A caller that is not the GuardDuty delegated administrator gets AccessDeniedException with the
    exact message on Create, Get and List of a rule's org configuration, and none is created; a delegated
    administrator gets ConflictException deleting a configuration an active association still uses."""
    gd = ctx.client("guardduty")

    # CreateCustomDetectionRuleOrgConfiguration/ListCustomDetectionRules operate against the
    # account's detector -- without one, ListCustomDetectionRules is rejected outright with
    # BadRequestException ("no detector was found for your account").
    detector_id = gd.create_detector(Enable=True)["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    # positive control: the account/detector are otherwise healthy for this API surface, so a
    # denial below is the delegated-admin boundary, not a blanket-broken caller.
    rules = gd.list_custom_detection_rules().get("Rules", [])
    if not rules:
        raise AssertionError(
            "ListCustomDetectionRules returned no AWS-managed custom detection rules in this "
            "account/region; there is no RuleId available to configure at the org level. This "
            "closes once at least one custom detection rule is published for the account/region."
        )
    rule_id = rules[0]["RuleId"]
    mode = "DRY_RUN"

    try:
        gd.create_custom_detection_rule_org_configuration(RuleId=rule_id, Mode=mode)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "AccessDeniedException", (
            "expected the documented delegated-admin-only boundary (AccessDeniedException) on "
            f"CreateCustomDetectionRuleOrgConfiguration for a non-delegated-admin caller, got {code!r}"
        )
        assert message == _DENIED_MESSAGE, f"expected message {_DENIED_MESSAGE!r}, got {message!r}"
        # effect absent, at an independent read: this caller is denied Get and List for the
        # org-configuration family exactly as it was denied Create -- no configuration was
        # fabricated for rule_id as a side effect of the refused create.
        get_code, get_message = _error_code(
            lambda: gd.get_custom_detection_rule_org_configuration(RuleId=rule_id, Mode=mode)
        )
        assert get_code == "AccessDeniedException", (
            f"expected GetCustomDetectionRuleOrgConfiguration to be denied the same way, got {get_code!r}"
        )
        assert get_message == _DENIED_MESSAGE, f"expected message {_DENIED_MESSAGE!r}, got {get_message!r}"
        try:
            listing = gd.list_custom_detection_rule_org_configurations()
        except ClientError as exc:
            list_code = exc.response["Error"]["Code"]
            list_message = exc.response["Error"].get("Message")
            assert list_code == "AccessDeniedException", (
                f"expected ListCustomDetectionRuleOrgConfigurations to be denied the same way, got {list_code!r}"
            )
            assert list_message == _DENIED_MESSAGE, (
                f"expected message {_DENIED_MESSAGE!r}, got {list_message!r}"
            )
        else:
            configs = listing.get("Configurations", [])
            assert not any(c.get("RuleId") == rule_id for c in configs), (
                "denied create must not have produced a listed org configuration"
            )
        return

    def _cleanup_org_config() -> None:
        try:
            gd.delete_custom_detection_rule_org_configuration(RuleId=rule_id, Mode=mode)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_org_config)
    _wait_for_org_config_active(ctx, rule_id, mode)

    assoc = gd.create_custom_detection_rule_association(RuleId=rule_id, Mode=mode)
    assoc_id = assoc["RuleAssociation"]["AssociationId"]

    def _cleanup_assoc() -> None:
        try:
            gd.delete_custom_detection_rule_association(RuleId=rule_id, AssociationId=assoc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_assoc)

    # message not asserted: this branch runs only for a delegated administrator, and neither the
    # API model nor the docs give the conflict's wording
    code, _ = _error_code(
        lambda: gd.delete_custom_detection_rule_org_configuration(RuleId=rule_id, Mode=mode)
    )
    assert code == "ConflictException", (
        f"expected ConflictException while an active association still references the rule, got {code!r}"
    )

    # effect absent: the org configuration is still present (delete was rejected, not applied)
    cfg = gd.get_custom_detection_rule_org_configuration(RuleId=rule_id, Mode=mode)["Configuration"]
    assert cfg["Status"] in ("ACTIVE", "PROCESSING"), (
        f"expected the org configuration to still be present after the rejected delete, got status {cfg['Status']!r}"
    )

    # positive control: once the blocking association is removed, the same delete call succeeds
    gd.delete_custom_detection_rule_association(RuleId=rule_id, AssociationId=assoc_id)
    gd.delete_custom_detection_rule_org_configuration(RuleId=rule_id, Mode=mode)


_DENIED_MESSAGE = "The request is rejected because the caller is not authorized to call this API."


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_org_config_active(ctx, rule_id: str, mode: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    gd = ctx.client("guardduty")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cfg = gd.get_custom_detection_rule_org_configuration(RuleId=rule_id, Mode=mode)["Configuration"]
        last_status = cfg["Status"]
        if last_status == "ACTIVE":
            return
        if last_status == "FAILED":
            raise AssertionError(f"org configuration for rule {rule_id} transitioned to FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"org configuration for rule {rule_id} never reached ACTIVE (last status {last_status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
