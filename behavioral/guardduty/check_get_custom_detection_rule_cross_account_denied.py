"""get-custom-detection-rule-cross-account-denied."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-custom-detection-rule-cross-account-denied"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]

# NOTE on scope: GuardDuty custom detection rules are a shared, AWS-managed catalog -- their ARN
# is arn:aws:guardduty::aws:detection-rule/custom/<RuleId> (a fixed "aws" account segment, not a
# per-customer-owned resource), and there is no CreateCustomDetectionRule API: customers can only
# associate their detector with catalog rules via CreateCustomDetectionRuleAssociation. Because
# these rules aren't per-account resources, IAM resource-level ARN scoping does not create the
# per-resource boundary a true cross-account test would need (an Allow scoped to one rule's ARN
# does not authorize a get of a different, real rule either). What IS real and exercisable in a
# single account is the actual boundary this action
# enforces: guardduty:GetCustomDetectionRule requires that specific IAM permission -- a caller
# explicitly denied it is rejected with AccessDeniedException rather than the read silently
# succeeding, and a RuleId that doesn't exist in the catalog (the same shape a truly foreign
# identifier would have) is rejected with ResourceNotFoundException rather than being returned.


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """A role allowed guardduty:GetCustomDetectionRule reads a catalog rule; a Deny on that action makes
    the call fail with the exact AccessDeniedException while an unrestricted caller still reads the rule,
    removing the Deny restores it, and an unknown RuleId gets the exact ResourceNotFoundException."""
    gd = ctx.client("guardduty")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    existing_detectors = gd.list_detectors().get("DetectorIds", [])
    detector_id = existing_detectors[0] if existing_detectors else gd.create_detector(Enable=True)["DetectorId"]
    if not existing_detectors:
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    rules = gd.list_custom_detection_rules().get("Rules", [])
    rule_ids = sorted({r["RuleId"] for r in rules if r.get("RuleId")})
    if not rule_ids:
        raise AssertionError(
            "this account's GuardDuty custom detection rule catalog (ListCustomDetectionRules) "
            "exposes zero rules; at least 1 real rule is needed as the positive-control target "
            "for a denied GetCustomDetectionRule call. This becomes exercisable once GuardDuty "
            "Extended Threat Detection custom detection rules are exposed to this "
            "account/organization."
        )
    real_rule_id = rule_ids[0]
    action = "guardduty:GetCustomDetectionRule"

    role = _create_allow_role(ctx, account_id, [action])
    # GuardDuty keeps a session's authorization once evaluated, so every probe below reads
    # through a fresh role session to observe a policy change.
    def restricted_gd():
        return _assume_role_client(ctx, role["role_arn"])

    # --- Positive control: the allow-only role can already read the real rule, before any deny
    #     is attached -- otherwise a role denied EVERYTHING would pass this check too.
    positive_ok = _poll_until(
        lambda: _call_succeeds(lambda: restricted_gd().get_custom_detection_rule(RuleId=real_rule_id)),
        lambda ok: ok,
        timeout_s=180.0,
        interval_s=3.0,
        description="the allow policy for guardduty:GetCustomDetectionRule becomes effective",
    )
    assert positive_ok, "the allow-only role must read the real rule before any deny is attached"

    # --- Break exactly one thing: deny that same action on the same role.
    deny_policy_name = "deny-inline"
    ctx.on_cleanup(lambda: _delete_role_policy_if_present(ctx, role["role_name"], deny_policy_name))
    _put_deny_policy(ctx, role["role_name"], deny_policy_name, [action])

    _poll_until(
        lambda: _call_succeeds(lambda: restricted_gd().get_custom_detection_rule(RuleId=real_rule_id)),
        lambda ok: not ok,
        timeout_s=180.0,
        interval_s=3.0,
        description="the deny policy for guardduty:GetCustomDetectionRule becomes effective",
    )
    denied = _error(lambda: restricted_gd().get_custom_detection_rule(RuleId=real_rule_id))
    assert denied["Code"] == "AccessDeniedException", f"expected AccessDeniedException, got {denied!r}"
    expected_denied = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role['role_name']}/sim2real-behav-session "
        f"is not authorized to perform: {action} on resource: "
        f"arn:aws:guardduty:{ctx.region}:{account_id}:* with an explicit deny in an identity-based "
        "policy"
    )
    assert denied["Message"] == expected_denied, (
        f"expected message {expected_denied!r}, got {denied['Message']!r}"
    )

    # --- Effect absent: the deny is scoped to this one role; an unrestricted caller still reads
    #     the same rule unaffected.
    admin_read = gd.get_custom_detection_rule(RuleId=real_rule_id)
    assert admin_read["Rule"]["RuleId"] == real_rule_id, (
        "an unrestricted caller could no longer read the real rule while the role-scoped deny was "
        "in effect"
    )

    # --- Restore: remove the deny; the identical call must succeed again.
    _delete_role_policy_if_present(ctx, role["role_name"], deny_policy_name)
    restored_ok = _poll_until(
        lambda: _call_succeeds(lambda: restricted_gd().get_custom_detection_rule(RuleId=real_rule_id)),
        lambda ok: ok,
        timeout_s=180.0,
        interval_s=3.0,
        description="the restricted role's read is restored after the deny is removed",
    )
    assert restored_ok, "removing the deny policy must restore the identical call to success"

    missing_rule_id = f"sim2real{uuid.uuid4().hex}"[:32]
    missing = _error(lambda: gd.get_custom_detection_rule(RuleId=missing_rule_id))
    assert missing["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent RuleId, got {missing!r}"
    )
    expected_missing = f"Rule not found: {missing_rule_id}"
    assert missing["Message"] == expected_missing, (
        f"expected message {expected_missing!r}, got {missing['Message']!r}"
    )


def _error(fn):
    """The botocore Error dict. Raises on unexpected SUCCESS."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _call_succeeds(fn):
    """Polling-only: True/False without raising, for convergence checks on the positive/restore
    legs where a transient AccessDenied is expected while IAM propagates."""
    try:
        fn()
    except ClientError:
        return False
    return True


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last saw {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _create_allow_role(ctx, account_id, allowed_actions):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-gd-deny-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": allowed_actions, "Resource": "*"}],
    }
    policy_name = "allow-inline"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(allow_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return {"role_name": role_name, "role_arn": role_arn}


def _put_deny_policy(ctx, role_name, policy_name, denied_actions):
    iam = ctx.client("iam")
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": denied_actions, "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(deny_policy)
    )


def _delete_role_policy_if_present(ctx, role_name, policy_name):
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _assume_role_client(ctx, role_arn):
    sts = ctx.client("sts")
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-behav-session"
            )["Credentials"]
            return ctx.client(
                "guardduty",
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as err:
            last_err = err
            time.sleep(3.0)
    raise AssertionError(f"could not assume role {role_arn} in time: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

