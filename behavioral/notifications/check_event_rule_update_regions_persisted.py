"""event-rule-update-regions-persisted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-rule-update-regions-persisted"
GROUP = "state"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateEventRule's new `regions` list is durably persisted and observable via
    GetEventRule once the rule settles back out of UPDATING."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)
    second_region = _pick_other_region(ctx.region)

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real update-rule check",
        tags={"sim2real-env": "behavioral"},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))

    rule_arn = notif.create_event_rule(
        notificationConfigurationArn=config_arn,
        source="aws.ec2",
        eventType="EC2 Instance State-change Notification",
        regions=[ctx.region],
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_rule(notif, rule_arn))

    initial_status = _poll_until(
        lambda: notif.get_event_rule(arn=rule_arn)["statusSummaryByRegion"].get(ctx.region, {}).get("status"),
        lambda status: status in ("ACTIVE", "INACTIVE"),
        timeout_s=90,
        interval_s=3,
    )
    assert initial_status == "ACTIVE", f"EventRule never settled to ACTIVE in {ctx.region}, got {initial_status!r}"

    notif.update_event_rule(arn=rule_arn, regions=[second_region])

    final_regions = _poll_until(
        lambda: notif.get_event_rule(arn=rule_arn)["regions"],
        lambda regions: regions == [second_region],
        timeout_s=90,
        interval_s=3,
    )
    assert final_regions == [second_region], f"regions did not persist, got {final_regions!r}"

    final_status = _poll_until(
        lambda: notif.get_event_rule(arn=rule_arn)["statusSummaryByRegion"].get(second_region, {}).get("status"),
        lambda status: status in ("ACTIVE", "INACTIVE"),
        timeout_s=90,
        interval_s=3,
    )
    assert final_status == "ACTIVE", f"EventRule settled to {final_status!r} in {second_region}, expected ACTIVE"
    assert ctx.region not in notif.get_event_rule(arn=rule_arn)["statusSummaryByRegion"], (
        f"old region {ctx.region} still present in statusSummaryByRegion after update"
    )


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are served only in us-east-1, so the client is
    pinned there; an emulator target ignores the region pin."""
    return ctx.client("notifications", region="us-east-1")


def _pick_other_region(region: str) -> str:
    for candidate in ("us-west-2", "eu-west-1", "ap-southeast-2", "eu-central-1"):
        if candidate != region:
            return candidate
    return "us-east-1"


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
    try:
        notif.delete_event_rule(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value: {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

