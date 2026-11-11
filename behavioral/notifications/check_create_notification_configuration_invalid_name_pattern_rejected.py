"""create-notification-configuration-invalid-name-pattern-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-notification-configuration-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["notifications"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNotificationConfiguration rejects a name containing characters
    outside [A-Za-z0-9_-] with ValidationException, no configuration is created
    for it, while a name using only the allowed character set succeeds."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)
    bad_name = ctx.unique_name("sim2real behav ") + "!"

    code, message = _client_error(
        lambda: notif.create_notification_configuration(name=bad_name, description="should be rejected")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value at 'name' failed to satisfy constraint: Member must satisfy "
        r"regular expression pattern: [A-Za-z0-9_\-]+"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    existing_names = _all_names(notif)
    assert bad_name not in existing_names, "a configuration was created despite the invalid name"

    # Positive control: a name using only the allowed RFC 3986 unreserved characters.
    good_name = ctx.unique_name("sim2real-behav-")
    good_arn = notif.create_notification_configuration(
        name=good_name, description="should succeed", tags={"sim2real": "true"}
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, good_arn))

    got = notif.get_notification_configuration(arn=good_arn)
    assert got["name"] == good_name, f"expected name {good_name!r}, got {got['name']!r}"


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are available only in us-east-1;
    pin the client there via ctx's own region override, which keeps the emulator's
    shared endpoint and dummy creds on that arm and only affects real AWS's regional
    endpoint resolution."""
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


def _all_names(notif):
    names = []
    token = None
    while True:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = notif.list_notification_configurations(**kwargs)
        names.extend(c["name"] for c in resp["notificationConfigurations"])
        token = resp.get("nextToken")
        if not token:
            return names


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
