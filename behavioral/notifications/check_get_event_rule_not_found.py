"""get-event-rule-not-found."""
from __future__ import annotations

import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-event-rule-not-found"
GROUP = "error-semantics"
SERVICES = ["notifications"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetEventRule on a well-formed never-created ARN fails with ResourceNotFoundException and the
    exact message, while GetEventRule on a rule the check created succeeds."""
    # AWS User Notifications' control-plane APIs are available only in us-east-1.
    notif = ctx.client("notifications", region="us-east-1")
    _ensure_notification_hub(notif)

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"), description="sim2real get-event-rule-not-found check"
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))
    notif.tag_resource(arn=config_arn, tags={"sim2real-check": CHECK})

    rule_arn = notif.create_event_rule(
        notificationConfigurationArn=config_arn,
        source="aws.ec2",
        eventType="EC2 Instance State-change Notification",
        regions=[ctx.region],
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_rule(notif, rule_arn))

    real = notif.get_event_rule(arn=rule_arn)
    assert real["arn"] == rule_arn, f"positive control: expected {rule_arn!r}, got {real.get('arn')!r}"

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_config_id = _random_id()
    fake_rule_id = _random_id()
    arn = f"arn:aws:notifications::{account_id}:configuration/{fake_config_id}/rule/{fake_rule_id}"

    code, message = _error_code(lambda: notif.get_event_rule(arn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == f"event rule with arn {arn} not found", f"unexpected not-found message: {message!r}"


def _random_id() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=27))


def _error_code(fn) -> tuple[str, str]:
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded with {resp!r}")


def _ensure_notification_hub(notif):
    """CreateNotificationConfiguration requires at least one ACTIVE NotificationHub
    (an account-level Region enablement, independent of any single check's own
    resources). Register one if the account has none yet; NEVER deregister it
    afterward — AWS itself refuses to deregister an account's LAST remaining hub
    (ConflictException), and other checks running in the same account depend on
    it existing."""
    resp = notif.list_notification_hubs(maxResults=3)
    if any(h.get("statusSummary", {}).get("status") == "ACTIVE" for h in resp.get("notificationHubs", [])):
        return
    try:
        notif.register_notification_hub(notificationHubRegion=notif.meta.region_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConflictException":
            raise
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        resp = notif.list_notification_hubs(maxResults=3)
        if any(h.get("statusSummary", {}).get("status") == "ACTIVE" for h in resp.get("notificationHubs", [])):
            return
        time.sleep(3)
    raise AssertionError("no ACTIVE NotificationHub became available within 90s")


def _safe_delete_rule(notif, arn, timeout_s=300.0, interval_s=5.0):
    """Delete the rule, waiting out the ConflictException AWS returns while it is still
    CREATING in some region."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            notif.delete_event_rule(arn=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _safe_delete_config(notif, arn, timeout_s=300.0, interval_s=5.0):
    """Delete the configuration, waiting out the ConflictException AWS returns while one of
    its event rules is still DELETING in some region."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            notif.delete_notification_configuration(arn=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
