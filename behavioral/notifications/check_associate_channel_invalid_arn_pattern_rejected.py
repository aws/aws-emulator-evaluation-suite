"""associate-channel-invalid-arn-pattern-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-channel-invalid-arn-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["notifications"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateChannel with a Channel ARN outside the chatbot, consoleapp and notifications-contacts
    namespaces fails with ValidationException and the exact message and is not associated, while a
    real supported Channel associates."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real invalid-channel-arn check",
        tags={"sim2real-env": "behavioral", "sim2real-owner": "checks"},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))

    bogus_channel_arn = f"arn:aws:sns:{ctx.region}:123456789012:not-a-supported-channel-type"
    code, message = _client_error(
        lambda: notif.associate_channel(arn=bogus_channel_arn, notificationConfigurationArn=config_arn)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value at 'arn' failed to satisfy constraint: Member must satisfy "
        "regular expression pattern: "
        r"arn:[a-z-]{3,10}:(chatbot|consoleapp|notifications-contacts):[a-zA-Z0-9-]*:[0-9]{12}:"
        r"[a-zA-Z0-9-_.@]+/[a-zA-Z0-9/_.@:-]+"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    arns_after_reject = _channel_arns(notif, config_arn)
    assert bogus_channel_arn not in arns_after_reject, (
        f"rejected channel {bogus_channel_arn!r} unexpectedly present in {arns_after_reject!r}"
    )

    # Positive control: a real, supported-namespace Channel still associates fine.
    real_channel_arn = _create_email_contact_channel(ctx)
    notif.associate_channel(arn=real_channel_arn, notificationConfigurationArn=config_arn)
    ctx.on_cleanup(lambda: _safe_disassociate(notif, real_channel_arn, config_arn))

    arns_after_control = _channel_arns(notif, config_arn)
    assert real_channel_arn in arns_after_control, "positive control association did not take effect"


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are available only in us-east-1;
    pin the client there on real AWS regardless of ctx.region via ctx.client's own
    region override (the emulator shares one endpoint regardless of region, so this
    is a no-op there)."""
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
    """notifications-contacts is likewise us-east-1-only; same region-pin idiom."""
    return ctx.client("notificationscontacts", region="us-east-1")


def _create_email_contact_channel(ctx) -> str:
    contacts = _contacts_client(ctx)
    resp = contacts.create_email_contact(
        emailAddress=f"{ctx.unique_name('sim2real-behav')}@example.com",
        name=ctx.unique_name("sim2real-contact-"),
        tags={"sim2real-env": "behavioral", "sim2real-owner": "checks"},
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
