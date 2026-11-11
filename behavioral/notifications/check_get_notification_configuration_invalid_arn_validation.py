"""get-notification-configuration-invalid-arn-validation."""
from __future__ import annotations

import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-notification-configuration-invalid-arn-validation"
GROUP = "error-semantics"
SERVICES = ["notifications"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetNotificationConfiguration rejects a malformed ARN with ValidationException and a well-formed
    missing ARN with ResourceNotFoundException, each with the exact message, while a real
    configuration reads back."""
    notif = _notifications_client(ctx)
    _ensure_notification_hub(notif)

    # Positive control: a real, just-created configuration's own
    # GetNotificationConfiguration succeeds -- so a rejection below is specific
    # to the bad ARN, not the caller's credentials being unable to call
    # GetNotificationConfiguration at all.
    real_arn = notif.create_notification_configuration(
        name=ctx.unique_name("sim2real-behav-"), description="sim2real invalid-arn-validation check"
    )["arn"]
    ctx.on_cleanup(lambda: _safe_delete_config(notif, real_arn))
    control = notif.get_notification_configuration(arn=real_arn)
    assert control["arn"] == real_arn, f"expected {real_arn!r}, got {control.get('arn')!r}"

    # Syntactically invalid ARN: rejected before any lookup.
    code, message = _client_error(lambda: notif.get_notification_configuration(arn="not-a-valid-arn"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value at 'arn' failed to satisfy constraint: Member must satisfy "
        r"regular expression pattern: arn:[a-z-]{3,10}:notifications::[0-9]{12}:configuration/[a-z0-9]{27}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Well-formed but never-created ARN: a DIFFERENT, more specific refusal --
    # proves the malformed-ARN case above is a syntax rejection, not just
    # "any ARN this check didn't create comes back the same way".
    fake_arn = f"arn:aws:notifications::{ctx.account}:configuration/{_random_id()}"
    missing_code, missing_message = _client_error(lambda: notif.get_notification_configuration(arn=fake_arn))
    assert missing_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {missing_code!r}"
    )
    expected_missing = f"notification configuration with arn {fake_arn} not found"
    assert missing_message == expected_missing, f"expected message {expected_missing!r}, got {missing_message!r}"


def _notifications_client(ctx):
    """AWS User Notifications' control-plane APIs are served only from us-east-1;
    ctx.client's region override pins the client there on every target."""
    return ctx.client("notifications", region="us-east-1")


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
    try:
        notif.delete_notification_configuration(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _random_id() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=27))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
