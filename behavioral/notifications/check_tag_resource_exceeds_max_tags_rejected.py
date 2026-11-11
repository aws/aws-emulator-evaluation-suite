"""tag-resource-exceeds-max-tags-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-max-tags-rejected"
GROUP = "overly-permissive"
SERVICES = ["notifications"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tags map exceeding the 200-entry quota with
    ValidationException and applies none of them, while a map within the quota
    is accepted in full."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)

    arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"), description="sim2real too-many-tags check"
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, arn))

    too_many_tags = {f"sim2real-tag-{i}": str(i) for i in range(201)}
    code, message = _client_error(lambda: notif.tag_resource(arn=arn, tags=too_many_tags))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "[object has too many properties (found 201 but schema requires at most 200)]"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tags_after_reject = notif.list_tags_for_resource(arn=arn).get("tags", {})
    assert tags_after_reject == {}, "some tags were persisted despite exceeding the quota"

    # Positive control: a tag map within the quota is applied in full.
    ok_tags = {f"sim2real-tag-{i}": str(i) for i in range(5)}
    notif.tag_resource(arn=arn, tags=ok_tags)
    tags_after_control = notif.list_tags_for_resource(arn=arn)["tags"]
    assert tags_after_control == ok_tags, f"expected {ok_tags} applied in full, got {tags_after_control}"


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
