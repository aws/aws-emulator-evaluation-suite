"""custom-detection-rule-association-lifecycle."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "custom-detection-rule-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["guardduty"]


_ASSOC_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c5",
    "concern:negative-classes",
    "concern:representation",
    "plane:control", "resource:account-singleton:guardduty-detector",
)
def run(ctx) -> None:
    """A DRY_RUN association with a catalog rule carries ExpiresAt; Update to LIVE clears it and
    advances UpdatedAt only, List shows it once, and after Delete (idempotent) Get and Update return
    the exact ResourceNotFoundException, as do Create, Get and Update for a never-created RuleId."""
    gd = ctx.client("guardduty")
    _get_or_create_detector(ctx, gd)

    rule_id = _pick_unassociated_rule(gd)
    if rule_id is None:
        raise AssertionError(
            "every rule in this account's GuardDuty custom detection rule catalog "
            "(ListCustomDetectionRules) already has an association; none is free to drive "
            "this check's create->update->delete lifecycle without disturbing an association "
            "this check does not own"
        )

    # ----- real lifecycle: DRY_RUN -> LIVE -> deleted, against a real catalog rule -----
    created = gd.create_custom_detection_rule_association(
        RuleId=rule_id, Mode="DRY_RUN", Tags=dict(_ASSOC_TAGS)
    )["RuleAssociation"]
    association_id = created["AssociationId"]
    ctx.on_cleanup(
        lambda: gd.delete_custom_detection_rule_association(
            RuleId=rule_id, AssociationId=association_id
        )
    )

    # independent read #1: a DRY_RUN association carries an expiry
    after_create = gd.get_custom_detection_rule_association(
        RuleId=rule_id, AssociationId=association_id
    )["RuleAssociation"]
    assert after_create["Mode"] == "DRY_RUN", after_create
    assert after_create["AssociationId"] == association_id, after_create
    assert after_create.get("ExpiresAt") is not None, (
        f"expected a DRY_RUN association to carry ExpiresAt, got {after_create!r}"
    )
    created_at = after_create["CreatedAt"]
    updated_at_after_create = after_create["UpdatedAt"]

    gd.update_custom_detection_rule_association(
        RuleId=rule_id, AssociationId=association_id, Mode="LIVE"
    )

    # independent read #2: LIVE clears the expiry and advances UpdatedAt, not CreatedAt
    after_update = gd.get_custom_detection_rule_association(
        RuleId=rule_id, AssociationId=association_id
    )["RuleAssociation"]
    assert after_update["Mode"] == "LIVE", after_update
    assert after_update.get("ExpiresAt") is None, (
        f"expected LIVE to clear ExpiresAt, got {after_update!r}"
    )
    assert after_update["CreatedAt"] == created_at, "CreatedAt must not change on update"
    assert after_update["UpdatedAt"] > updated_at_after_create, (
        f"expected UpdatedAt to advance past the create-time value "
        f"{updated_at_after_create!r}, got {after_update['UpdatedAt']!r}"
    )

    # list: exactly this association, reflecting the now-current LIVE mode
    listed = gd.list_custom_detection_rule_associations(RuleId=rule_id).get(
        "RuleAssociations", []
    )
    matching = [a for a in listed if a["AssociationId"] == association_id]
    assert len(matching) == 1, f"expected exactly 1 association for {rule_id}, got {matching}"
    assert matching[0]["Mode"] == "LIVE", matching[0]

    gd.delete_custom_detection_rule_association(RuleId=rule_id, AssociationId=association_id)

    # gone: an independent read returns the specific not-found code
    _expect_not_found(
        lambda: gd.get_custom_detection_rule_association(
            RuleId=rule_id, AssociationId=association_id
        ),
        f"Association not found: {association_id}",
    )

    # unusable: a mutation on the dead id also fails not-found
    _expect_not_found(
        lambda: gd.update_custom_detection_rule_association(
            RuleId=rule_id, AssociationId=association_id, Mode="DRY_RUN"
        ),
        f"Association not found: {association_id}",
    )

    # idempotent-delete semantics: deleting an already-deleted association succeeds silently
    gd.delete_custom_detection_rule_association(RuleId=rule_id, AssociationId=association_id)

    # ----- never-existent RuleId: uniformly rejected, no association ever appears -----
    missing_rule_id = uuid.uuid4().hex
    missing_association_id = uuid.uuid4().hex

    _expect_not_found(
        lambda: gd.create_custom_detection_rule_association(RuleId=missing_rule_id, Mode="LIVE"),
        f"Rule not found: {missing_rule_id}",
    )

    _expect_not_found(
        lambda: gd.get_custom_detection_rule(RuleId=missing_rule_id),
        f"Rule not found: {missing_rule_id}",
    )

    _expect_not_found(
        lambda: gd.get_custom_detection_rule_association(
            RuleId=missing_rule_id, AssociationId=missing_association_id
        ),
        f"Association not found: {missing_association_id}",
    )

    _expect_not_found(
        lambda: gd.update_custom_detection_rule_association(
            RuleId=missing_rule_id, AssociationId=missing_association_id, Mode="DRY_RUN"
        ),
        f"Association not found: {missing_association_id}",
    )

    # DeleteCustomDetectionRuleAssociation is idempotent-delete semantics: deleting an
    # association that never existed succeeds silently (no ResourceNotFoundException),
    # unlike Create/Get/Update which all validate RuleId existence first.
    gd.delete_custom_detection_rule_association(
        RuleId=missing_rule_id, AssociationId=missing_association_id
    )

    # No association was ever created for this RuleId -- confirm it is absent from the list.
    paginator_kwargs = {}
    seen_rule_ids = set()
    while True:
        resp = gd.list_custom_detection_rule_associations(**paginator_kwargs)
        for assoc in resp.get("RuleAssociations", []):
            seen_rule_ids.add(assoc.get("RuleId"))
        next_token = resp.get("NextToken")
        if not next_token:
            break
        paginator_kwargs = {"NextToken": next_token}
    assert missing_rule_id not in seen_rule_ids, "no association should exist for a never-created rule"


def _expect_not_found(fn, expected_message: str) -> None:
    """Call fn() and require ResourceNotFoundException with exactly ``expected_message``. An
    unexpected SUCCESS raises: a target that answers a dead id must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
    else:
        raise AssertionError(
            f"expected ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}"
        )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _get_or_create_detector(ctx, gd):
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0], False
    resp = gd.create_detector(Enable=True, Tags=dict(_ASSOC_TAGS))
    detector_id = resp["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id, True


def _pick_unassociated_rule(gd):
    """Return a RuleId from the shared, AWS-managed detection-rule catalog
    (ListCustomDetectionRules) that has no existing association, or None if every
    catalog rule already has one. There is no CreateCustomDetectionRule API -- the
    catalog is fixed -- so this is how the check gets a real RuleId to drive the
    lifecycle without colliding with an association it does not own."""
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
