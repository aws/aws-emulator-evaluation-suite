"""list-notification-configurations-filters-by-status."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-notification-configurations-filters-by-status"
GROUP = "list"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNotificationConfigurations' status filter returns a freshly created
    (zero-EventRules, so INACTIVE) config under status=INACTIVE and excludes it
    under status=ACTIVE."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)

    arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"),
        description="sim2real list-status check",
        tags={"sim2real-env": "behavioral", "sim2real-owner": "checks"},
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, arn))

    _poll_until(
        lambda: _collect_arns(notif, status="INACTIVE"),
        lambda arns: arn in arns,
        timeout_s=60,
        interval_s=3,
    )

    active_arns = _collect_arns(notif, status="ACTIVE")
    assert arn not in active_arns, "INACTIVE config incorrectly present in status=ACTIVE filter results"


def _notifications_client(ctx):
    """notifications is served in us-east-1 whatever the run's region; ctx.client's overrides pin
    the endpoint and the signing region on every target."""
    return ctx.client("notifications", region="us-east-1")


def _collect_arns(notif, status):
    arns = []
    token = None
    while True:
        kwargs = {"status": status, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = notif.list_notification_configurations(**kwargs)
        arns.extend(c["arn"] for c in resp["notificationConfigurations"])
        token = resp.get("nextToken")
        if not token:
            return arns


def _collect_arns_unfiltered(notif):
    arns = []
    token = None
    while True:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = notif.list_notification_configurations(**kwargs)
        arns.extend(c["arn"] for c in resp["notificationConfigurations"])
        token = resp.get("nextToken")
        if not token:
            return arns


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


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
