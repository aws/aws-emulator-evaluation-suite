"""autoshift-observer-notification-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "autoshift-observer-notification-round-trip"
GROUP = "state"
SERVICES = ["arc-zonal-shift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:arc-zonal-shift-observer-notification")
def run(ctx) -> None:
    """UpdateAutoshiftObserverNotificationStatus toggles the account/region-level setting and
    GetAutoshiftObserverNotificationStatus reflects the new value, then round-trips back."""
    arc = ctx.client("arc-zonal-shift")

    original = arc.get_autoshift_observer_notification_status()["status"]
    ctx.on_cleanup(
        lambda: arc.update_autoshift_observer_notification_status(status=original)
    )

    other = "DISABLED" if original == "ENABLED" else "ENABLED"
    arc.update_autoshift_observer_notification_status(status=other)
    got = arc.get_autoshift_observer_notification_status()["status"]
    assert got == other, f"expected status {other!r} after update, got {got!r}"

    arc.update_autoshift_observer_notification_status(status=original)
    got_back = arc.get_autoshift_observer_notification_status()["status"]
    assert got_back == original, f"expected status back to {original!r}, got {got_back!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
