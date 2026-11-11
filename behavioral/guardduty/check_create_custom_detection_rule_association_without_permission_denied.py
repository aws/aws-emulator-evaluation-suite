"""create-custom-detection-rule-association-without-permission-denied."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-custom-detection-rule-association-without-permission-denied"
GROUP = "negative-classes"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateCustomDetectionRuleAssociation by a principal without permissions raises
    AccessDeniedException with the exact message and creates nothing, while the same call by a
    permitted caller raises ResourceNotFoundException.
    """
    gd = ctx.client("guardduty")
    iam = ctx.client("iam")

    # CreateCustomDetectionRuleAssociation (and ListCustomDetectionRuleAssociations)
    # require an enabled detector to exist in the account/region; GuardDuty allows only
    # one detector per account/region, so adopt an existing one rather than erroring on
    # CreateDetector's "detector already exists" rejection, and only clean up what this
    # check itself created.
    _get_or_create_detector(ctx, gd)

    # positive control: a properly-permissioned caller can reach the GuardDuty API
    gd.list_detectors()

    rule_id = uuid.uuid4().hex  # matches CreateCustomDetectionRuleAssociation's
    # RuleId pattern ([a-z0-9]+(-[a-z0-9]+)*). GuardDuty exposes no CreateCustomDetectionRule
    # (or equivalent) API -- custom detection rules can only be authored through the console
    # today -- so a real rule can't be provisioned here; see
    # custom_detection_rule_association_lifecycle.py.

    # positive control on the operation itself: the SAME call, fully permissioned, fails for
    # a DIFFERENT, non-authorization reason (the RuleId doesn't exist). Without this, "denied
    # for lack of permission" would be indistinguishable from "denied because the RuleId is
    # fake, regardless of who calls".
    try:
        admin_resp = gd.create_custom_detection_rule_association(RuleId=rule_id, Mode="DRY_RUN")
    except ClientError as exc:
        admin_code = exc.response["Error"]["Code"]
        admin_message = exc.response["Error"].get("Message")
    else:
        admin_assoc_id = admin_resp["RuleAssociation"]["AssociationId"]
        ctx.on_cleanup(
            lambda: gd.delete_custom_detection_rule_association(
                RuleId=rule_id, AssociationId=admin_assoc_id
            )
        )
        raise AssertionError(
            "a fully-permissioned caller's CreateCustomDetectionRuleAssociation with a fake "
            f"RuleId unexpectedly SUCCEEDED (AssociationId={admin_assoc_id!r}); expected "
            "ResourceNotFoundException"
        )
    assert admin_code == "ResourceNotFoundException", (
        "expected the permissioned caller's identical call to fail on RuleId existence "
        f"(ResourceNotFoundException), got {admin_code!r}"
    )
    expected_admin_message = f"Rule not found: {rule_id}"
    assert admin_message == expected_admin_message, (
        f"expected message {expected_admin_message!r}, got {admin_message!r}"
    )

    user_name = ctx.unique_name("sim2real-gd-nopriv-")
    iam.create_user(
        UserName=user_name,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    restricted_gd = _wait_for_restricted_client(ctx, key)

    code, message = _error_code(
        lambda: restricted_gd.create_custom_detection_rule_association(
            RuleId=rule_id, Mode="DRY_RUN"
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    action = "guardduty:CreateCustomDetectionRuleAssociation"
    expected_message = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"{action} on resource: arn:aws:guardduty:{ctx.region}:{ctx.account}:"
        f"detection-rule/custom/{rule_id}/association/* because no identity-based policy "
        f"allows the {action} action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no association was created for this RuleId
    assocs = gd.list_custom_detection_rule_associations().get("RuleAssociations", [])
    assert all(a.get("RuleId") != rule_id for a in assocs), (
        f"an association for RuleId={rule_id!r} exists despite the denied "
        "CreateCustomDetectionRuleAssociation call"
    )


def _get_or_create_detector(ctx, gd):
    """GuardDuty allows only one detector per account/region; adopt an existing one
    instead of erroring on CreateDetector's "detector already exists" rejection, and
    tag + register cleanup only for a detector this check itself created."""
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0]
    detector_id = gd.create_detector(
        Enable=True,
        Tags={"sim2real:managed": "true", "sim2real:check": CHECK},
    )["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected a ClientError from real AWS, but the call SUCCEEDED and returned {result!r}"
    )


def _wait_for_restricted_client(ctx, key, timeout_s: float = 25.0):
    """Build a guardduty client signed with freshly-minted, zero-permission IAM
    credentials against the same target as ctx's client, and poll until the
    credentials have propagated (distinguishing "not yet active" from "active but
    denied")."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        client = ctx.client(
            "guardduty",
            creds={
                "aws_access_key_id": key["AccessKeyId"],
                "aws_secret_access_key": key["SecretAccessKey"],
            },
        )
        try:
            client.list_detectors()
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code in (
                "InvalidClientTokenId",
                "InvalidAccessKeyId",
                "UnrecognizedClientException",
            ):
                time.sleep(1.5)
                continue
            return client  # credentials are active (denied for a permission reason)
        else:
            return client  # credentials are active and the call happened to succeed
    raise AssertionError(f"IAM credentials never became active (last error: {last_code})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
