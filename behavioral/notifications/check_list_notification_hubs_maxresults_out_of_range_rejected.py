"""list-notification-hubs-maxresults-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-notification-hubs-maxresults-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["notifications"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListNotificationHubs sent with maxResults 5 or 1 (client-side validation off; the modeled range is
    exactly 3) fails with ValidationException and the exact message, while maxResults=3 is accepted."""
    notif = _notifications_client(ctx, validate_params=False)

    prefix = "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
    code, message = _client_error(lambda: notif.list_notification_hubs(maxResults=5))
    assert code == "ValidationException", f"expected ValidationException for maxResults=5, got {code!r}"
    expected_high = prefix + "Member must have value less than or equal to 3"
    assert message == expected_high, f"expected message {expected_high!r}, got {message!r}"

    code_low, message_low = _client_error(lambda: notif.list_notification_hubs(maxResults=1))
    assert code_low == "ValidationException", f"expected ValidationException for maxResults=1, got {code_low!r}"
    expected_low = prefix + "Member must have value greater than or equal to 3"
    assert message_low == expected_low, f"expected message {expected_low!r}, got {message_low!r}"

    # Positive control: the one value the fixed range actually allows.
    resp = notif.list_notification_hubs(maxResults=3)
    assert "notificationHubs" in resp


def _notifications_client(ctx, *, validate_params: bool = True):
    """AWS User Notifications' control-plane APIs are served only from us-east-1;
    ctx.client's region override pins the client there on every target.

    ``validate_params=False`` disables botocore's client-side parameter
    validation, so an intentionally out-of-range value (this check's whole point)
    reaches the wire instead of being rejected locally by the SDK."""
    from botocore.config import Config

    return ctx.client("notifications", region="us-east-1", config=Config(parameter_validation=validate_params))


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
