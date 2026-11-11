"""concurrent-associate-channel-exactly-one-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-associate-channel-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent identical AssociateChannel calls for one channel and configuration all succeed
    (a repeat is idempotent) and the channel is listed exactly once; after DisassociateChannel it is
    not listed."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)
    channel_arn = _create_email_contact_channel(ctx)
    racer_count = 5

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real concurrent-associate check",
        tags={"sim2real": "true"},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))
    ctx.on_cleanup(lambda: _safe_disassociate(notif, channel_arn, config_arn))

    def _racer(_: int):
        try:
            notif.associate_channel(arn=channel_arn, notificationConfigurationArn=config_arn)
            return "ok"
        except ClientError as exc:
            return exc.response["Error"]["Code"]

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    assert all(r == "ok" for r in results), f"expected every identical racer to succeed idempotently, got {results!r}"

    arns = _channel_arns(notif, config_arn)
    assert arns.count(channel_arn) == 1, f"channel appears {arns.count(channel_arn)} times after the race"

    notif.disassociate_channel(arn=channel_arn, notificationConfigurationArn=config_arn)
    arns_after = _channel_arns(notif, config_arn)
    assert channel_arn not in arns_after, f"channel still listed after disassociate: {arns_after!r}"


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are available only in us-east-1;
    pin the client there on real AWS regardless of ctx.region (an emulator shares
    one endpoint regardless of region, so this is a no-op there)."""
    return ctx.client("notifications", region="us-east-1")


def _contacts_client(ctx) -> Any:
    """notificationscontacts is likewise pinned to us-east-1 on real AWS."""
    return ctx.client("notificationscontacts", region="us-east-1")


def _create_email_contact_channel(ctx) -> str:
    contacts = _contacts_client(ctx)
    resp = contacts.create_email_contact(
        emailAddress=f"{ctx.unique_name('sim2real-behav')}@example.com",
        name=ctx.unique_name("sim2real-contact-"),
        tags={"sim2real": "true"},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

