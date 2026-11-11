"""concurrent-event-rule-creation-yields-distinct-rules."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-event-rule-creation-yields-distinct-rules"
GROUP = "concurrency"
SERVICES = ["notifications"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateEventRule calls for the same (source, eventType) on one configuration yield
    exactly one winner and ConflictException with the exact message for every other caller, and
    ListEventRules holds only the winner's rule."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)
    racer_count = 5

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real concurrent-create-rule check",
        tags={"sim2real": CHECK},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))

    def _create(i: int):
        try:
            resp = notif.create_event_rule(
                notificationConfigurationArn=config_arn,
                source="aws.ec2",
                eventType="EC2 Instance State-change Notification",
                regions=[ctx.region],
            )
            return ("ok", resp["arn"])
        except ClientError as exc:
            return (exc.response["Error"]["Code"], exc.response["Error"]["Message"])

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_create, range(racer_count)))

    winners = [arn for code, arn in results if code == "ok"]
    losers = [code for code, _ in results if code != "ok"]
    loser_messages = [message for code, message in results if code != "ok"]
    for arn in winners:
        ctx.on_cleanup(lambda arn=arn: _safe_delete_rule(notif, arn))

    assert len(winners) == 1, f"expected exactly one winner, got results {results!r}"
    assert len(losers) == racer_count - 1, f"expected {racer_count - 1} ConflictException losers, got {results!r}"
    assert all(code == "ConflictException" for code in losers), f"unexpected loser error code(s): {losers!r}"
    expected = (
        "EventRule with source aws.ec2 and eventType EC2 Instance State-change Notification "
        f"already exists in NotificationConfiguration with arn {config_arn}."
    )
    for message in loser_messages:
        assert message == expected, f"ConflictException message {message!r}"

    rules = notif.list_event_rules(notificationConfigurationArn=config_arn)["eventRules"]
    matching = [r for r in rules if r["source"] == "aws.ec2" and r["eventType"] == "EC2 Instance State-change Notification"]
    assert len(matching) == 1, f"expected exactly one persisted rule for the pair, found {len(matching)}"
    assert matching[0]["arn"] == winners[0], "the persisted rule does not match the concurrency winner's ARN"


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are available only in us-east-1;
    pin the client there via ctx.client's region override rather than hand-rolling
    boto3.client (an emulator shares one endpoint regardless of region, so ctx.client
    already makes this a no-op there)."""
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


def _delete_when_settled(fn, timeout_s=300.0):
    """Teardown: call the delete; gone is done. A rule still CREATING refuses the delete of itself and
    of its configuration with ConflictException ("has not reached terminal status"), retried every 2 s."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ResourceNotFoundException":
                return
            if (err["Code"] != "ConflictException" or "has not reached terminal status" not in err.get("Message", "")
                    or time.monotonic() >= deadline):
                raise
        time.sleep(2)


def _safe_delete_rule(notif, arn):
    _delete_when_settled(lambda: notif.delete_event_rule(arn=arn))


def _safe_delete_config(notif, arn):
    _delete_when_settled(lambda: notif.delete_notification_configuration(arn=arn))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
