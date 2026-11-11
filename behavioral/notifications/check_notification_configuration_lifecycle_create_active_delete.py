"""notification-configuration-lifecycle-create-active-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notification-configuration-lifecycle-create-active-delete"
GROUP = "state"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new NotificationConfiguration with no EventRules is INACTIVE on create and on read; after
    delete, GetNotificationConfiguration and a second delete fail with ResourceNotFoundException and
    the exact message."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)
    name = ctx.unique_name("sim2real-behav-")

    created = notif.create_notification_configuration(
        name=name,
        description="sim2real behavioral check config",
        tags={"sim2real-env": "behavioral", "sim2real-owner": "checks"},
    )
    arn = created["arn"]

    def _cleanup():
        try:
            notif.delete_notification_configuration(arn=arn)
        except ClientError as exc:
            if _error_code_from(exc) != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # Freshly created with no EventRules reports INACTIVE, not ACTIVE.
    assert created["status"] == "INACTIVE", f"unexpected initial status {created['status']!r}"

    got = notif.get_notification_configuration(arn=arn)
    assert got["name"] == name
    assert got["status"] == "INACTIVE"

    notif.delete_notification_configuration(arn=arn)

    expected_message = f"notification configuration with arn {arn} not found"
    deadline = time.monotonic() + 60
    get_error = None
    while time.monotonic() < deadline:
        try:
            notif.get_notification_configuration(arn=arn)
        except ClientError as exc:
            get_error = (_error_code_from(exc), exc.response["Error"].get("Message"))
            if get_error[0] == "ResourceNotFoundException":
                break
        time.sleep(2)
    assert get_error is not None, "NotificationConfiguration was never fully removed after delete"
    assert get_error[0] == "ResourceNotFoundException", (
        f"GetNotificationConfiguration after delete returned {get_error[0]!r}, expected ResourceNotFoundException"
    )
    assert get_error[1] == expected_message, f"expected message {expected_message!r}, got {get_error[1]!r}"

    # The dead arn is not just unreadable -- it is unusable: a second delete on it must fail
    # the same specific way, not succeed silently or error differently.
    redelete_code, redelete_message = _client_error(lambda: notif.delete_notification_configuration(arn=arn))
    assert redelete_code == "ResourceNotFoundException", (
        f"delete on an already-removed NotificationConfiguration returned {redelete_code!r}, "
        "expected ResourceNotFoundException"
    )
    assert redelete_message == expected_message, (
        f"expected message {expected_message!r}, got {redelete_message!r}"
    )


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are available only in us-east-1;
    pin the client there via ctx.client's own region override (an emulator shares
    one endpoint regardless of region, so this is a no-op there)."""
    return ctx.client("notifications", region="us-east-1")


def _client_error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS
    raises, so a target accepting a call real AWS rejects fails loudly instead of
    reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _error_code_from(exc: ClientError):
    return exc.response["Error"]["Code"]


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

