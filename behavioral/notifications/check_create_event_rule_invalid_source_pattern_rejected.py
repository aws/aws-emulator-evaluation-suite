"""create-event-rule-invalid-source-pattern-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-event-rule-invalid-source-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["notifications"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventRule rejects a `source` that doesn't match the required
    `aws.<service>` EventBridge source pattern with ValidationException, no
    EventRule is created for it, while a valid source succeeds."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real invalid-source check",
        tags={"sim2real": "true"},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))

    code, message = _client_error(
        lambda: notif.create_event_rule(
            notificationConfigurationArn=config_arn,
            source="ec2",  # missing the mandatory "aws." prefix
            eventType="EC2 Instance State-change Notification",
            regions=[ctx.region],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value at 'source' failed to satisfy constraint: Member must satisfy "
        r"regular expression pattern: aws.([a-z0-9\-])+"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    rules_after_reject = notif.list_event_rules(notificationConfigurationArn=config_arn)["eventRules"]
    assert rules_after_reject == [], "an EventRule was created despite the invalid source"

    # Positive control: a properly-prefixed source succeeds.
    rule_arn = notif.create_event_rule(
        notificationConfigurationArn=config_arn,
        source="aws.ec2",
        eventType="EC2 Instance State-change Notification",
        regions=[ctx.region],
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_rule(notif, rule_arn))

    rules_after_control = notif.list_event_rules(notificationConfigurationArn=config_arn)["eventRules"]
    assert any(r["arn"] == rule_arn for r in rules_after_control), (
        f"expected {rule_arn!r} among {[r['arn'] for r in rules_after_control]!r} after the "
        "properly-prefixed source succeeded"
    )


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are available only in us-east-1;
    pin the client there via ctx's own region override, which keeps the emulator's
    shared endpoint and dummy creds on that arm and only affects real AWS's regional
    endpoint resolution."""
    return ctx.client("notifications", region="us-east-1")


def _safe_delete_rule(notif, arn):
    """Delete the rule, retrying while AWS refuses with ConflictException because
    the rule has not reached a terminal status yet (CREATING / UPDATING)."""
    _delete_when_settled(lambda: notif.delete_event_rule(arn=arn))


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


def _safe_delete_config(notif, arn):
    """Delete the configuration, retrying while one of its rules is still not in a
    terminal status (ConflictException); a configuration already gone is fine."""
    _delete_when_settled(lambda: notif.delete_notification_configuration(arn=arn))


def _delete_when_settled(delete, timeout_s=300):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _client_error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS
    raises, so a target accepting a call real AWS rejects fails loudly instead of
    reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
