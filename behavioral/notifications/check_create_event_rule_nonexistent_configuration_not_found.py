"""create-event-rule-nonexistent-configuration-not-found."""
from __future__ import annotations

import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-event-rule-nonexistent-configuration-not-found"
GROUP = "error-semantics"
SERVICES = ["notifications"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventRule and ListEventRules on a never-created notificationConfigurationArn fail with
    ResourceNotFoundException and the exact message, while the real configuration's own rule list
    holds only the rule created on it."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real create-event-rule-nonexistent-configuration check",
        tags={"sim2real-check": CHECK},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))

    # Positive control: the account, credentials and this exact call are healthy
    # against a configuration that actually exists.
    rule_arn = notif.create_event_rule(
        notificationConfigurationArn=config_arn,
        source="aws.ec2",
        eventType="EC2 Instance State-change Notification",
        regions=[ctx.region],
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_rule(notif, rule_arn))
    assert rule_arn.startswith(f"arn:aws:notifications::{account_id}:configuration/"), (
        f"positive-control rule arn {rule_arn!r} does not belong to this account"
    )

    fake_config_arn = f"arn:aws:notifications::{account_id}:configuration/{_random_id()}"
    code, message = _client_error(
        lambda: notif.create_event_rule(
            notificationConfigurationArn=fake_config_arn,
            source="aws.ec2",
            eventType="EC2 Instance State-change Notification",
            regions=[ctx.region],
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"notification configuration with arn {fake_config_arn} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent, via two independent reads (ListEventRules, never the
    # rejected CreateEventRule call): the never-created configuration cannot be
    # listed into either, and the real configuration's own rule list holds only
    # the positive control -- no orphan surfaced under either arn.
    list_code, list_message = _client_error(
        lambda: notif.list_event_rules(notificationConfigurationArn=fake_config_arn)
    )
    assert list_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {list_code!r}"
    assert list_message == expected_message, f"expected message {expected_message!r}, got {list_message!r}"

    rules = notif.list_event_rules(notificationConfigurationArn=config_arn)["eventRules"]
    assert [r["arn"] for r in rules] == [rule_arn], f"expected only the positive-control rule, found {rules}"


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
    """Delete the configuration, retrying while one of its rules is still not in a
    terminal status (ConflictException); a configuration already gone is fine."""
    _delete_when_settled(lambda: notif.delete_notification_configuration(arn=arn))


def _delete_when_settled(delete, timeout_s=300):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _safe_delete_rule(notif, arn):
    """Delete the rule, retrying while AWS refuses with ConflictException because
    the rule has not reached a terminal status yet (CREATING / UPDATING)."""
    _delete_when_settled(lambda: notif.delete_event_rule(arn=arn))


def _random_id() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=27))


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
