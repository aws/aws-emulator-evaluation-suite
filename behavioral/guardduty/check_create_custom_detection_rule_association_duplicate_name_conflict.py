"""create-custom-detection-rule-association-duplicate-name-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-custom-detection-rule-association-duplicate-name-conflict"
GROUP = "error-semantics"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A second CreateCustomDetectionRuleAssociation for the same rule and detector raises
    ConflictException with the exact message and keeps the first; after deleting it, Get raises
    ResourceNotFoundException and the create succeeds again.
    """
    gd = ctx.client("guardduty")
    _ensure_detector(ctx, gd)

    try:
        rule_id = _pick_unassociated_rule(gd)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError(
                "caller lacks permission to list custom detection rules/associations"
            )
        raise
    if rule_id is None:
        raise AssertionError(
            "no custom detection rule is available for this account without an "
            "existing association -- GuardDuty exposes no CreateCustomDetectionRule "
            "API, so a fresh RuleId can't be provisioned for the test; needs "
            "ListCustomDetectionRules to return at least one unassociated rule"
        )

    try:
        resp1 = gd.create_custom_detection_rule_association(
            RuleId=rule_id, Mode="DRY_RUN", Tags={"sim2real-check": CHECK}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError(
                "caller is not the GuardDuty delegated administrator for custom "
                "detection rules; single-account association calls require that role"
            )
        raise
    assoc_id = resp1["RuleAssociation"]["AssociationId"]
    ctx.on_cleanup(lambda aid=assoc_id: _delete_if_exists(gd, rule_id, aid))

    try:
        leaked = gd.create_custom_detection_rule_association(
            RuleId=rule_id, Mode="DRY_RUN", Tags={"sim2real-check": CHECK}
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        # An over-permissive target just created a second, real association -- register it for
        # cleanup before failing loudly.
        leaked_id = leaked["RuleAssociation"]["AssociationId"]
        ctx.on_cleanup(lambda aid=leaked_id: _delete_if_exists(gd, rule_id, aid))
        raise AssertionError(
            f"expected ConflictException creating a second association for RuleId={rule_id}, "
            f"but it succeeded and created AssociationId={leaked_id}"
        )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected_message = f"Association already exists for rule {rule_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: still exactly one association for this rule.
    assocs = gd.list_custom_detection_rule_associations(RuleId=rule_id).get("RuleAssociations", [])
    assert len(assocs) == 1 and assocs[0]["AssociationId"] == assoc_id, assocs

    # Positive control: the surviving association is still fully readable.
    detail = gd.get_custom_detection_rule_association(RuleId=rule_id, AssociationId=assoc_id)
    assert detail["RuleAssociation"]["Mode"] == "DRY_RUN", (
        f"expected surviving association {assoc_id} to read back Mode=DRY_RUN, "
        f"got {detail['RuleAssociation']}"
    )

    # Restore: deleting the blocking association lifts the conflict. The deleted
    # association becomes independently unreadable, and the identical create now
    # succeeds -- proving the rejection above was about the association, not the input.
    gd.delete_custom_detection_rule_association(RuleId=rule_id, AssociationId=assoc_id)
    try:
        gd.get_custom_detection_rule_association(RuleId=rule_id, AssociationId=assoc_id)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException reading the deleted association {assoc_id}, "
            f"got {exc.response['Error']['Code']}"
        )
        expected_message = f"Association not found: {assoc_id}"
        got_message = exc.response["Error"].get("Message")
        assert got_message == expected_message, (
            f"expected message {expected_message!r}, got {got_message!r}"
        )
    else:
        raise AssertionError(
            f"expected association {assoc_id} to be gone after delete, but it is still readable"
        )

    resp2 = gd.create_custom_detection_rule_association(
        RuleId=rule_id, Mode="DRY_RUN", Tags={"sim2real-check": CHECK}
    )
    assoc_id2 = resp2["RuleAssociation"]["AssociationId"]
    ctx.on_cleanup(lambda aid=assoc_id2: _delete_if_exists(gd, rule_id, aid))
    detail2 = gd.get_custom_detection_rule_association(RuleId=rule_id, AssociationId=assoc_id2)
    assert detail2["RuleAssociation"]["Mode"] == "DRY_RUN", (
        f"expected the post-restore association {assoc_id2} to read back Mode=DRY_RUN, "
        f"got {detail2['RuleAssociation']}"
    )


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


def _delete_if_exists(gd, rule_id, assoc_id):
    try:
        gd.delete_custom_detection_rule_association(RuleId=rule_id, AssociationId=assoc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _pick_unassociated_rule(gd):
    rules = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = gd.list_custom_detection_rules(**kwargs)
        rules.extend(resp.get("Rules", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    if not rules:
        return None

    associated = set()
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = gd.list_custom_detection_rule_associations(**kwargs)
        associated.update(a["RuleId"] for a in resp.get("RuleAssociations", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break

    for rule in rules:
        if rule["RuleId"] not in associated:
            return rule["RuleId"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
