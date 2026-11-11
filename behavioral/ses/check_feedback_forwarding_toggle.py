"""feedback-forwarding-toggle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "feedback-forwarding-toggle"
GROUP = 'identities'
SERVICES = ['ses']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIdentityFeedbackForwardingEnabled toggles ForwardingEnabled off and back on without any
    Bounce/Complaint SNS topics attached; the documented topic prerequisite is not enforced."""
    ses = ctx.client("ses")
    email = f"{ctx.unique_name('sim2real-behav-fwd-')}@example.com"
    ses.verify_email_identity(EmailAddress=email)
    ctx.on_cleanup(lambda: _quiet(lambda: ses.delete_identity(Identity=email)))

    def forwarding() -> bool:
        return ses.get_identity_notification_attributes(Identities=[email])[
            "NotificationAttributes"
        ][email]["ForwardingEnabled"]

    assert forwarding() is True, "freshly-verified identity did not default to ForwardingEnabled=True"

    ses.set_identity_feedback_forwarding_enabled(Identity=email, ForwardingEnabled=False)
    assert _poll_bool(lambda: forwarding() is False, timeout_s=60, interval_s=2), (
        "ForwardingEnabled never became False"
    )

    ses.set_identity_feedback_forwarding_enabled(Identity=email, ForwardingEnabled=True)
    assert _poll_bool(lambda: forwarding() is True, timeout_s=60, interval_s=2), (
        "ForwardingEnabled never returned to True"
    )


def _quiet(fn):
    """Best-effort teardown call — the resource may already be gone."""
    fn()


def _poll_bool(predicate, timeout_s=60, interval_s=2) -> bool:
    """Poll *predicate* until truthy (True) or *timeout_s* elapses (False).
    Exceptions mean "not yet"; SES attribute reads are eventually consistent."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            if predicate():
                return True
        except Exception:  # noqa: BLE001 — a read that fails yet is not a verdict
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
