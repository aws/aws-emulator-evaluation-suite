"""disassociate-channel-not-associated-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-channel-not-associated-rejected"
GROUP = "overly-permissive"
SERVICES = ["notifications"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateChannel for an existing Channel never associated with the configuration fails
    with ResourceNotFoundException and leaves the associated channel untouched; disassociating
    the real association still succeeds."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)
    associated_channel_arn = _create_email_contact_channel(ctx)
    unassociated_channel_arn = _create_email_contact_channel(ctx)

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real not-associated-disassociate check",
        tags={"sim2real-check": CHECK},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))
    ctx.on_cleanup(lambda: _safe_disassociate(notif, associated_channel_arn, config_arn))

    notif.associate_channel(arn=associated_channel_arn, notificationConfigurationArn=config_arn)

    code, message = _client_error(
        lambda: notif.disassociate_channel(arn=unassociated_channel_arn, notificationConfigurationArn=config_arn)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"channel with arn {unassociated_channel_arn} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    arns_after_reject = _channel_arns(notif, config_arn)
    assert associated_channel_arn in arns_after_reject, "the real association was disturbed by the rejected call"

    # Positive control: disassociating the channel that IS actually associated succeeds.
    notif.disassociate_channel(arn=associated_channel_arn, notificationConfigurationArn=config_arn)
    arns_after_control = _channel_arns(notif, config_arn)
    assert associated_channel_arn not in arns_after_control, "positive-control disassociation did not take effect"


# ===== helpers =====
def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are available only in us-east-1;
    pin the client there on real AWS regardless of ctx.region via ctx.client's own
    region override, which falls back to the shared emulator endpoint (rather than
    dropping it) when this is not real AWS."""
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
        tags={"sim2real-check": CHECK},
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
