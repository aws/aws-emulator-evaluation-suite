"""associate-channel-duplicate-association-is-idempotent."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-channel-duplicate-association-is-idempotent"
GROUP = "state"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeating AssociateChannel for the same (channel, configuration) pair succeeds and the
    channel is still listed exactly once; associating the same channel with a second
    configuration also succeeds and lists it under both without disturbing the first."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)
    channel_arn = _create_email_contact_channel(ctx)

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real duplicate-associate check",
        tags={"sim2real-behav": "true"},
    )["arn"]
    other_config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real duplicate-associate check (other config)",
        tags={"sim2real-behav": "true"},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))
    ctx.on_cleanup(lambda: _safe_delete_config(notif, other_config_arn))
    ctx.on_cleanup(lambda: _safe_disassociate(notif, channel_arn, config_arn))
    ctx.on_cleanup(lambda: _safe_disassociate(notif, channel_arn, other_config_arn))

    notif.associate_channel(arn=channel_arn, notificationConfigurationArn=config_arn)
    _poll_until(
        lambda: _channel_arns(notif, config_arn), lambda arns: channel_arn in arns, timeout_s=60, interval_s=3
    )

    # Repeating the SAME (channel, config) pair is idempotent, not an error.
    notif.associate_channel(arn=channel_arn, notificationConfigurationArn=config_arn)
    arns = _channel_arns(notif, config_arn)
    assert arns.count(channel_arn) == 1, f"channel appears {arns.count(channel_arn)} times, expected exactly 1"

    # Fan-out: the SAME channel can be associated with a second, different config too.
    notif.associate_channel(arn=channel_arn, notificationConfigurationArn=other_config_arn)
    arns_other = _poll_until(
        lambda: _channel_arns(notif, other_config_arn),
        lambda arns: channel_arn in arns,
        timeout_s=60,
        interval_s=3,
    )
    assert channel_arn in arns_other, "fan-out association to the second config did not take effect"
    assert channel_arn in _channel_arns(notif, config_arn), (
        "fan-out to a second config incorrectly disturbed the first association"
    )


# ===== helpers =====
def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are available only in us-east-1;
    pin the client there through `ctx.client(..., region=)`, which resolves correctly
    on both targets (real AWS: the pinned region; an emulator: its one shared endpoint,
    unaffected by the region override)."""
    return ctx.client("notifications", region="us-east-1")


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


def _contacts_client(ctx) -> Any:
    for name in ("notifications-contacts", "notificationscontacts"):
        try:
            return ctx.client(name, region="us-east-1")
        except Exception:
            continue
    raise AssertionError(
        "no boto3 client available for the User Notifications Contacts service; "
        "cannot provision the Channels needed for this check"
    )


def _create_email_contact_channel(ctx) -> str:
    contacts = _contacts_client(ctx)
    resp = contacts.create_email_contact(
        emailAddress=f"{ctx.unique_name('sim2real-behav')}@example.com",
        name=ctx.unique_name("sim2real-contact-"),
        tags={"sim2real-behav": "true"},
    )
    arn = resp["arn"]

    def _cleanup():
        try:
            contacts.delete_email_contact(arn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return arn


def _channel_arns(notif, config_arn):
    arns = []
    token = None
    while True:
        kwargs = {"notificationConfigurationArn": config_arn}
        if token:
            kwargs["nextToken"] = token
        resp = notif.list_channels(**kwargs)
        arns.extend(resp["channels"])
        token = resp.get("nextToken")
        if not token:
            return arns


def _safe_disassociate(notif, channel_arn, config_arn):
    try:
        notif.disassociate_channel(arn=channel_arn, notificationConfigurationArn=config_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_config(notif, arn):
    try:
        notif.delete_notification_configuration(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while True:
        if predicate(value):
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
