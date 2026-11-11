"""update-notification-configuration-changes-description."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-notification-configuration-changes-description"
GROUP = "state"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNotificationConfiguration durably persists a new description while
    leaving the name untouched."""
    # AWS User Notifications' control-plane APIs are served from a single home region,
    # us-east-1, regardless of ctx.region -- pin the client there rather than at ctx.region.
    notif = ctx.client("notifications", region="us-east-1")
    _ensure_notification_hub(notif)
    name = ctx.unique_name("sim2real-behav-")

    arn = notif.create_notification_configuration(
        name=name,
        description="original description",
        tags={"sim2real-env": "behavioral", "sim2real-owner": "checks"},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, arn))

    notif.update_notification_configuration(arn=arn, description="updated description")

    got = notif.get_notification_configuration(arn=arn)
    assert got["description"] == "updated description", (
        f"expected description 'updated description' after update, got {got['description']!r}"
    )
    assert got["name"] == name, (
        f"UpdateNotificationConfiguration must not change name: expected {name!r}, got {got['name']!r}"
    )


def _ensure_notification_hub(notif):
    """CreateNotificationConfiguration requires at least one ACTIVE NotificationHub
    (an account-level Region enablement, independent of any single check's own
    resources). Register one if the account has none yet; NEVER deregister it
    afterward -- AWS itself refuses to deregister an account's LAST remaining hub
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
    try:
        notif.delete_notification_configuration(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
