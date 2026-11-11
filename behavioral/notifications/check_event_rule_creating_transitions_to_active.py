"""event-rule-creating-transitions-to-active."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-rule-creating-transitions-to-active"
GROUP = "state"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created EventRule starts in CREATING and settles to ACTIVE for the
    Region it targets, as reported by GetEventRule's statusSummaryByRegion."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)

    config_arn = _create_config(ctx, notif)
    created = notif.create_event_rule(
        notificationConfigurationArn=config_arn,
        source="aws.cloudwatch",
        eventType="CloudWatch Alarm State Change",
        regions=[ctx.region],
    )
    rule_arn = created["arn"]
    ctx.on_cleanup(lambda: _safe_delete_rule(notif, rule_arn))

    final_status = _poll_until(
        lambda: notif.get_event_rule(arn=rule_arn)["statusSummaryByRegion"][ctx.region]["status"],
        lambda status: status in ("ACTIVE", "INACTIVE"),
        timeout_s=90,
        interval_s=3,
    )
    assert final_status == "ACTIVE", f"EventRule settled to {final_status!r}, expected ACTIVE"


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are served only from us-east-1;
    ctx.client's region override pins the client there on every target."""
    return ctx.client("notifications", region="us-east-1")


def _create_config(ctx, notif):
    arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real event-rule check",
        tags={"sim2real": CHECK},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, arn))
    return arn


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


def _safe_delete_rule(notif, arn):
    """Delete the rule, retrying while AWS refuses with ConflictException because
    the rule has not reached a terminal status yet (CREATING / UPDATING)."""
    _delete_when_settled(lambda: notif.delete_event_rule(arn=arn))


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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

