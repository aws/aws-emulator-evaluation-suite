"""associate-channel-then-list-channels-shows-association."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-channel-then-list-channels-shows-association"
GROUP = "state"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateChannel wires a real Channel (an email contact) to a
    NotificationConfiguration and it becomes visible via ListChannels."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)
    channel_arn = _create_email_contact_channel(ctx)

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real associate-channel check",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))

    notif.associate_channel(arn=channel_arn, notificationConfigurationArn=config_arn)
    ctx.on_cleanup(lambda: _safe_disassociate(notif, channel_arn, config_arn))

    _poll_until(
        lambda: _channel_arns(notif, config_arn),
        lambda arns: channel_arn in arns,
        timeout_s=60,
        interval_s=3,
        message=f"channel {channel_arn} never appeared in ListChannels for {config_arn}",
    )


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are available only in us-east-1;
    pin the client there regardless of ctx.region. ``region=`` overrides the region
    for this client only, leaving endpoint/credential wiring untouched, so it is a
    correct no-op against an emulator's single shared endpoint too."""
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


def _contacts_client(ctx):
    """User Notifications Contacts' control-plane APIs are available only in
    us-east-1, same rationale as ``_notifications_client``. ``notificationscontacts``
    (no hyphen) is the real boto3 service id."""
    return ctx.client("notificationscontacts", region="us-east-1")


def _create_email_contact_channel(ctx) -> str:
    contacts = _contacts_client(ctx)
    resp = contacts.create_email_contact(
        emailAddress=f"{ctx.unique_name('sim2real-behav')}@example.com",
        name=ctx.unique_name("sim2real-contact-"),
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, message="condition not met"):
    deadline = time.monotonic() + timeout_s
    while True:
        value = probe()
        if predicate(value):
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"{message} (timed out after {timeout_s}s, last saw: {value!r})")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
