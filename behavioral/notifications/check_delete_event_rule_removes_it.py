"""delete-event-rule-removes-it."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-event-rule-removes-it"
GROUP = "state"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteEventRule removes the rule from both GetEventRule (ResourceNotFound)
    and the parent NotificationConfiguration's ListEventRules."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real delete-rule check",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))

    rule_arn = notif.create_event_rule(
        notificationConfigurationArn=config_arn,
        source="aws.ec2",
        eventType="EC2 Instance State-change Notification",
        regions=[ctx.region],
    )["arn"]

    rules = notif.list_event_rules(notificationConfigurationArn=config_arn)["eventRules"]
    assert any(r["arn"] == rule_arn for r in rules), "created rule missing from ListEventRules"

    # DeleteEventRule is rejected with ConflictException while the rule is still
    # CREATING ("has not reached terminal status") -- wait for it to settle first.
    settled = _poll_until_settled(notif, rule_arn, ctx.region)
    assert settled == "ACTIVE", f"EventRule settled to {settled!r} before delete, expected ACTIVE"

    notif.delete_event_rule(arn=rule_arn)

    deadline = time.monotonic() + 60
    get_error = None
    while time.monotonic() < deadline:
        try:
            notif.get_event_rule(arn=rule_arn)
        except ClientError as exc:
            get_error = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            if get_error[0] == "ResourceNotFoundException":
                break
        time.sleep(2)
    assert get_error is not None, "EventRule was never removed from GetEventRule after delete"
    assert get_error[0] == "ResourceNotFoundException", (
        f"GetEventRule on a deleted rule expected ResourceNotFoundException, got {get_error[0]!r}"
    )
    expected_get_message = f"event rule with arn {rule_arn} not found"
    assert get_error[1] == expected_get_message, (
        f"expected message {expected_get_message!r}, got {get_error[1]!r}"
    )

    rules_after = notif.list_event_rules(notificationConfigurationArn=config_arn)["eventRules"]
    assert not any(r["arn"] == rule_arn for r in rules_after), "deleted rule still present in ListEventRules"

    mutation_code, mutation_message = _client_error(
        lambda: notif.update_event_rule(arn=rule_arn, regions=[ctx.region])
    )
    assert mutation_code == "ResourceNotFoundException", (
        f"UpdateEventRule on a deleted rule expected ResourceNotFoundException, got {mutation_code!r}"
    )
    expected_update_message = f"EventRule with arn {rule_arn} not found"
    assert mutation_message == expected_update_message, (
        f"expected message {expected_update_message!r}, got {mutation_message!r}"
    )


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are available only in us-east-1;
    pin the client there regardless of ctx.region. ``region=`` overrides the region
    for this client only, leaving endpoint/credential wiring untouched, so it is a
    correct no-op against an emulator's single shared endpoint too."""
    return ctx.client("notifications", region="us-east-1")


def _poll_until_settled(notif, rule_arn, region, *, timeout_s=90, interval_s=3):
    deadline = time.monotonic() + timeout_s
    while True:
        status = notif.get_event_rule(arn=rule_arn)["statusSummaryByRegion"][region]["status"]
        if status in ("ACTIVE", "INACTIVE"):
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"EventRule stuck at {status!r} after {timeout_s}s, never reached a terminal status")
        time.sleep(interval_s)


def _client_error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS
    raises, so a target accepting a call real AWS rejects fails loudly instead of
    reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
