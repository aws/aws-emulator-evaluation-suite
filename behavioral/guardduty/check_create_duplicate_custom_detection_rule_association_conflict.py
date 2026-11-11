"""create-duplicate-custom-detection-rule-association-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-duplicate-custom-detection-rule-association-conflict"
GROUP = "error-semantics"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A duplicate CreateCustomDetectionRuleAssociation for the same rule/mode is rejected with ConflictException."""
    gd = ctx.client("guardduty")

    # CreateCustomDetectionRuleAssociation/ListCustomDetectionRules operate against the account's
    # detector -- without one, ListCustomDetectionRules is itself rejected with BadRequestException
    # ("no detector was found for your account"). GuardDuty allows only one detector per
    # account/region and rejects a second CreateDetector outright, so adopt one if present rather
    # than always creating a fresh one.
    existing_detectors = gd.list_detectors().get("DetectorIds", [])
    if existing_detectors:
        detector_id = existing_detectors[0]
    else:
        detector_id = gd.create_detector(Enable=True, Tags={"sim2real-check": CHECK})["DetectorId"]
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    rule_id = _pick_unassociated_rule(gd)
    if rule_id is None:
        raise AssertionError(
            "ListCustomDetectionRules returned no AWS-managed custom detection rule in this "
            "account/region that is not already associated; there is no RuleId available to "
            "associate. This closes once at least one custom detection rule is published for "
            "the account/region under test and not already associated."
        )

    assoc = gd.create_custom_detection_rule_association(
        RuleId=rule_id, Mode="DRY_RUN", Tags={"sim2real-check": CHECK}
    )
    assoc_id = assoc["RuleAssociation"]["AssociationId"]
    ctx.on_cleanup(lambda: gd.delete_custom_detection_rule_association(RuleId=rule_id, AssociationId=assoc_id))

    # positive control: the association we just created is retrievable
    got = gd.get_custom_detection_rule_association(RuleId=rule_id, AssociationId=assoc_id)
    assert got["RuleAssociation"]["AssociationId"] == assoc_id, got
    assert got["RuleAssociation"]["Mode"] == "DRY_RUN", got

    code, message = _error_code(
        lambda: gd.create_custom_detection_rule_association(RuleId=rule_id, Mode="DRY_RUN")
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = f"Association already exists for rule {rule_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: still exactly one association for this rule (duplicate was not created)
    associations = gd.list_custom_detection_rule_associations().get("RuleAssociations", [])
    matching = [a for a in associations if a["RuleId"] == rule_id]
    assert len(matching) == 1, f"expected exactly 1 association for rule {rule_id}, found {len(matching)}"
    assert matching[0]["AssociationId"] == assoc_id, matching


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the duplicate association call to be rejected, but it succeeded: {result!r}")


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
