"""identity-headers-in-notifications-toggle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "identity-headers-in-notifications-toggle"
GROUP = 'identity'
SERVICES = ['ses']

def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIdentityHeadersInNotificationsEnabled toggles header inclusion for the targeted notification type only."""
    ses = ctx.client("ses")
    email = _unique_email(ctx, "hdrs-")
    ses.verify_email_identity(EmailAddress=email)
    ctx.on_cleanup(lambda _n=email: ses.delete_identity(Identity=_n))

    def notif_attrs():
        return ses.get_identity_notification_attributes(Identities=[email])[
            "NotificationAttributes"
        ][email]

    base = notif_attrs()
    # Defaults: original headers are not included, and feedback forwarding is on.
    assert base["HeadersInBounceNotificationsEnabled"] is False, base
    assert base["HeadersInComplaintNotificationsEnabled"] is False, base
    assert base["ForwardingEnabled"] is True, base

    ses.set_identity_headers_in_notifications_enabled(
        Identity=email, NotificationType="Bounce", Enabled=True
    )
    _poll_until(
        lambda: notif_attrs()["HeadersInBounceNotificationsEnabled"],
        lambda v: v is True,
        timeout_s=60,
        interval_s=2.0,
        description="HeadersInBounceNotificationsEnabled == True",
    )

    # The flag is scoped to the notification type that was set.
    assert notif_attrs()["HeadersInComplaintNotificationsEnabled"] is False, (
        "toggling Bounce headers must not affect Complaint headers"
    )

    ses.set_identity_headers_in_notifications_enabled(
        Identity=email, NotificationType="Bounce", Enabled=False
    )
    _poll_until(
        lambda: notif_attrs()["HeadersInBounceNotificationsEnabled"],
        lambda v: v is False,
        timeout_s=60,
        interval_s=2.0,
        description="HeadersInBounceNotificationsEnabled == False",
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
