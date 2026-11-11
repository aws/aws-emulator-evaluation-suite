"""get-managed-notification-configuration-matches-list-entry."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-managed-notification-configuration-matches-list-entry"
GROUP = "read"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetManagedNotificationConfiguration for an ARN returned by
    ListManagedNotificationConfigurations reports the identical name/description
    that the list entry advertised."""
    notif = _notifications_client(ctx)

    listed = notif.list_managed_notification_configurations(maxResults=5).get(
        "managedNotificationConfigurations", []
    )
    if not listed:
        raise AssertionError(
            "account/partition has no AWS-managed NotificationConfigurations to read; "
            "cannot exercise GetManagedNotificationConfiguration without one"
        )

    entry = listed[0]
    got = notif.get_managed_notification_configuration(arn=entry["arn"])

    assert got["arn"] == entry["arn"], f"expected arn {entry['arn']!r}, got {got['arn']!r}"
    assert got["name"] == entry["name"], (
        f"expected name {entry['name']!r} from the list entry, got {got['name']!r}"
    )
    assert got["description"] == entry["description"], (
        f"expected description {entry['description']!r} from the list entry, "
        f"got {got['description']!r}"
    )
    assert isinstance(got["category"], str) and got["category"], (
        f"expected a non-empty category string, got {got['category']!r}"
    )
    assert isinstance(got["subCategory"], str) and got["subCategory"], (
        f"expected a non-empty subCategory string, got {got['subCategory']!r}"
    )


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are served only from us-east-1;
    ctx.client's region override pins the client there on every target."""
    return ctx.client("notifications", region="us-east-1")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
