"""disassociate-channel-removes-association-and-allows-reassociation."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-channel-removes-association-and-allows-reassociation"
GROUP = "state"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateChannel removes the association from ListChannels, and the same
    Channel can be re-associated with the same NotificationConfiguration afterward."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)
    channel_arn = _create_email_contact_channel(ctx)

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real disassociate-channel check",
        tags={"sim2real": CHECK},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))
    ctx.on_cleanup(lambda: _safe_disassociate(notif, channel_arn, config_arn))

    notif.associate_channel(arn=channel_arn, notificationConfigurationArn=config_arn)
    after_associate = _poll_until(
        lambda: _channel_arns(notif, config_arn),
        lambda arns: channel_arn in arns,
        timeout_s=60,
        interval_s=3,
        description="AssociateChannel to be visible in ListChannels",
    )
    assert channel_arn in after_associate, "channel not listed after AssociateChannel"

    notif.disassociate_channel(arn=channel_arn, notificationConfigurationArn=config_arn)
    after_disassociate = _poll_until(
        lambda: _channel_arns(notif, config_arn),
        lambda arns: channel_arn not in arns,
        timeout_s=60,
        interval_s=3,
        description="DisassociateChannel to be reflected in ListChannels",
    )
    assert channel_arn not in after_disassociate, "channel still listed after DisassociateChannel"

    notif.associate_channel(arn=channel_arn, notificationConfigurationArn=config_arn)
    after_reassociate = _poll_until(
        lambda: _channel_arns(notif, config_arn),
        lambda arns: channel_arn in arns,
        timeout_s=60,
        interval_s=3,
        description="re-AssociateChannel to be visible in ListChannels",
    )
    assert channel_arn in after_reassociate, "re-association of a disassociated channel did not succeed"


# ===== helpers =====
def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are available only in us-east-1;
    pin the client there via ctx.client's region override, which leaves the
    endpoint/credential wiring unchanged (a no-op on an emulator, which shares
    one endpoint regardless of region)."""
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
        "no boto3 client available for the User Notifications Contacts service "
        "(tried 'notifications-contacts' and 'notificationscontacts'); cannot "
        "provision a real Channel to associate"
    )


def _create_email_contact_channel(ctx) -> str:
    contacts = _contacts_client(ctx)
    resp = contacts.create_email_contact(
        emailAddress=f"{ctx.unique_name('sim2real-behav')}@example.com",
        name=ctx.unique_name("sim2real-contact-"),
        tags={"sim2real": CHECK},
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
