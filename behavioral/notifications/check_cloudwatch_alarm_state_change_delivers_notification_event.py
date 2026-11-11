"""cloudwatch-alarm-state-change-delivers-notification-event."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudwatch-alarm-state-change-delivers-notification-event"
GROUP = "event-propagation"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventRule for CloudWatch Alarm State Change turns a real alarm transition into a
    NotificationEvent with non-empty content that names the rule's notification configuration."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)
    cw = ctx.client("cloudwatch")

    config_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real cloudwatch event-propagation check",
        aggregationDuration="NONE",
        tags={"sim2real-owner": "checks"},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, config_arn))

    rule_arn = notif.create_event_rule(
        notificationConfigurationArn=config_arn,
        source="aws.cloudwatch",
        eventType="CloudWatch Alarm State Change",
        eventPattern=json.dumps({"detail": {"state": {"value": ["ALARM"]}}}),
        regions=[ctx.region],
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_rule(notif, rule_arn))

    _poll_until(
        lambda: notif.get_event_rule(arn=rule_arn)["statusSummaryByRegion"][ctx.region]["status"],
        lambda status: status == "ACTIVE",
        timeout_s=120,
        interval_s=3,
        description=f"EventRule {rule_arn} reaching ACTIVE",
    )

    alarm_name = ctx.unique_name("sim2real-behav-alarm-")
    start_time = datetime.now(timezone.utc) - timedelta(seconds=5)
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        ComparisonOperator="GreaterThanThreshold",
        EvaluationPeriods=1,
        MetricName=ctx.unique_name("sim2real-metric-"),
        Namespace="Sim2RealBehavioral",
        Period=60,
        Statistic="Average",
        Threshold=1.0,
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-owner", "Value": "checks"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real behavioral trigger")

    matched = _poll_until(
        lambda: _find_matching_event(notif, config_arn, start_time),
        lambda event: event is not None,
        timeout_s=300,
        interval_s=10,
        description="NotificationEvent for the CloudWatch alarm transition",
    )

    full = notif.get_notification_event(arn=matched["arn"])
    assert full["notificationConfigurationArn"] == config_arn, (
        f"expected NotificationEvent's own configuration arn to be {config_arn!r}, got {full['notificationConfigurationArn']!r}"
    )
    assert full["content"], "NotificationEvent content was empty"


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


def _find_matching_event(notif, config_arn, start_time):
    resp = notif.list_notification_events(source="aws.cloudwatch", startTime=start_time, maxResults=50)
    for event in resp.get("notificationEvents", []):
        if event["notificationConfigurationArn"] == config_arn:
            return event
    return None


def _safe_delete_rule(notif, arn):
    """Delete the rule, retrying while AWS refuses with ConflictException because
    the rule has not reached a terminal status yet (CREATING / UPDATING)."""
    _delete_when_settled(lambda: notif.delete_event_rule(arn=arn))


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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    assert predicate(value), f"timed out after {timeout_s}s waiting for {description}; last observed: {value!r}"
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
