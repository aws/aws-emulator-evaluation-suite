"""get-notifications-access-for-organization-reports-status."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-notifications-access-for-organization-reports-status"
GROUP = "read"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetNotificationsAccessForOrganization succeeds for the calling account and reports a documented
    accessStatus (ENABLED, DISABLED, PENDING or FAILED); ListNotificationConfigurations also succeeds."""
    notif = _notifications_client(ctx)

    try:
        resp = notif.get_notifications_access_for_organization()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        raise AssertionError(
            f"expected GetNotificationsAccessForOrganization to succeed for this "
            f"caller, got {code!r}"
        ) from exc

    status = resp["notificationsAccessForOrganization"]["accessStatus"]
    assert status in ("ENABLED", "DISABLED", "PENDING", "FAILED"), f"unexpected accessStatus {status!r}"

    # Positive control: an ordinary, non-organizational call on the same client still
    # works fine, proving the caller's Notifications access generally, independent of
    # this one status report.
    resp = notif.list_notification_configurations(maxResults=10)
    assert "notificationConfigurations" in resp, (
        f"expected an ordinary ListNotificationConfigurations call to succeed with a "
        f"notificationConfigurations key, got response keys {sorted(resp.keys())!r}"
    )


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are available only in us-east-1;
    ctx.client's region override pins it there without disturbing endpoint/credential
    wiring (a no-op on an emulator, which shares one endpoint regardless of region)."""
    return ctx.client("notifications", region="us-east-1")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
