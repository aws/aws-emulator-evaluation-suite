"""list-event-rules-reflects-created-rule."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-event-rules-reflects-created-rule"
GROUP = "list"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEventRules for a NotificationConfiguration reflects a just-created
    EventRule with the exact source/eventType/regions it was created with."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"), description="sim2real list-rules check"
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))

    rule_arn = notif.create_event_rule(
        notificationConfigurationArn=config_arn,
        source="aws.ec2",
        eventType="EC2 Instance State-change Notification",
        regions=[ctx.region],
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_rule(notif, rule_arn))

    rules = notif.list_event_rules(notificationConfigurationArn=config_arn)["eventRules"]
    matches = [r for r in rules if r["arn"] == rule_arn]
    assert len(matches) == 1, f"expected exactly one matching rule, found {len(matches)}"
    rule = matches[0]
    assert rule["source"] == "aws.ec2", f"expected source aws.ec2, got {rule['source']!r}"
    assert rule["eventType"] == "EC2 Instance State-change Notification", (
        f"expected eventType 'EC2 Instance State-change Notification', got {rule['eventType']!r}"
    )
    assert rule["regions"] == [ctx.region], f"expected regions [{ctx.region!r}], got {rule['regions']!r}"
    assert rule["notificationConfigurationArn"] == config_arn, (
        f"expected notificationConfigurationArn {config_arn!r}, got {rule['notificationConfigurationArn']!r}"
    )


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are served only from us-east-1;
    ctx.client's region override pins the client there on every target."""
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
