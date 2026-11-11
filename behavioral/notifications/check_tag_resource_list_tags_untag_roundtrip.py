"""tag-resource-list-tags-untag-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-list-tags-untag-roundtrip"
GROUP = "state"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource's tags are visible via ListTagsForResource, and UntagResource
    durably removes them."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)

    arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"), description="sim2real tagging check"
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, arn))

    initial_tags = notif.list_tags_for_resource(arn=arn).get("tags", {})
    assert initial_tags == {}, f"expected a fresh configuration to have no tags, got {initial_tags!r}"

    notif.tag_resource(arn=arn, tags={"sim2real-env": "behavioral", "sim2real-owner": "checks"})

    tags = notif.list_tags_for_resource(arn=arn)["tags"]
    assert tags["sim2real-env"] == "behavioral", f"expected sim2real-env=behavioral, got {tags.get('sim2real-env')!r}"
    assert tags["sim2real-owner"] == "checks", f"expected sim2real-owner=checks, got {tags.get('sim2real-owner')!r}"

    notif.untag_resource(arn=arn, tagKeys=["sim2real-env"])

    tags_after = notif.list_tags_for_resource(arn=arn)["tags"]
    assert "sim2real-env" not in tags_after, (
        f"expected sim2real-env removed by UntagResource, still present: {tags_after!r}"
    )
    assert tags_after["sim2real-owner"] == "checks", (
        f"expected untouched tag sim2real-owner=checks to survive, got {tags_after.get('sim2real-owner')!r}"
    )


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are served only from us-east-1;
    ctx.client's region override pins the client there on every target."""
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


def _safe_delete_config(notif, arn):
    try:
        notif.delete_notification_configuration(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
