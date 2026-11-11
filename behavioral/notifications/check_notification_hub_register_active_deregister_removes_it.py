"""notification-hub-register-active-deregister-removes-it."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notification-hub-register-active-deregister-removes-it"
GROUP = "state"
SERVICES = ["notifications"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A hub registered in a second Region reaches ACTIVE in ListNotificationHubs;
    DeregisterNotificationHub removes it, and a repeat deregister fails with ResourceNotFoundException
    and the exact message."""
    # AWS User Notifications' control-plane APIs (Register/Deregister/ListNotificationHubs) are
    # served from a single home region, us-east-1, regardless of which region a hub's data plane
    # covers -- pin the client there rather than at ctx.region.
    notif = ctx.client("notifications", region="us-east-1")
    baseline_region = notif.meta.region_name
    hub_region = _pick_other_region(baseline_region)

    _ensure_baseline_hub(notif, baseline_region)

    # Best-effort: if a prior failed run left a hub registered in our target region,
    # remove it first so this check starts from a known state.
    if _find_hub(notif, hub_region) is not None:
        _safe_deregister(notif, hub_region)
        _poll_until(lambda: _find_hub(notif, hub_region), lambda hub: hub is None, timeout_s=60, interval_s=3)

    notif.register_notification_hub(notificationHubRegion=hub_region)
    ctx.on_cleanup(lambda: _safe_deregister(notif, hub_region))

    final_hub = _poll_until(
        lambda: _find_hub(notif, hub_region),
        lambda hub: hub is not None and hub["statusSummary"]["status"] in ("ACTIVE", "INACTIVE"),
        timeout_s=90,
        interval_s=3,
    )
    assert final_hub is not None, "registered hub never appeared in ListNotificationHubs"
    assert final_hub["statusSummary"]["status"] == "ACTIVE", (
        f"hub settled to {final_hub['statusSummary']['status']!r}, expected ACTIVE"
    )

    notif.deregister_notification_hub(notificationHubRegion=hub_region)

    removed = _poll_until(
        lambda: _find_hub(notif, hub_region),
        lambda hub: hub is None,
        timeout_s=90,
        interval_s=3,
    )
    assert removed is None, "hub still present in ListNotificationHubs after deregister"

    try:
        notif.deregister_notification_hub(notificationHubRegion=hub_region)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"re-deregistering an already-removed hub raised {code!r}, expected ResourceNotFoundException"
        )
        message = exc.response["Error"].get("Message")
        expected_message = f"notification hub with region {hub_region} not found"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    else:
        raise AssertionError(
            "re-deregistering an already-removed hub succeeded; expected ResourceNotFoundException"
        )


def _pick_other_region(region: str) -> str:
    """Any region other than `region` will do -- the candidates are not asserted on
    individually, only used as distinct `notificationHubRegion` values, so a fixed set of
    always-enabled commercial regions is sufficient (no discovery call needed)."""
    for candidate in ("eu-west-1", "us-west-2", "ap-southeast-2", "eu-central-1"):
        if candidate != region:
            return candidate
    return "us-east-1"


def _ensure_baseline_hub(notif, region):
    """Register (idempotently) a permanent baseline hub in `region` and wait
    for it to settle ACTIVE. Never deregistered by this check -- it exists so
    the check's OWN disposable hub is never the account's last remaining one."""
    if _find_hub(notif, region) is None:
        try:
            notif.register_notification_hub(notificationHubRegion=region)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                raise
    baseline = _poll_until(
        lambda: _find_hub(notif, region),
        lambda hub: hub is not None and hub["statusSummary"]["status"] == "ACTIVE",
        timeout_s=90,
        interval_s=3,
    )
    assert baseline is not None and baseline["statusSummary"]["status"] == "ACTIVE", (
        f"baseline hub in {region} never reached ACTIVE (prerequisite for the rest of this check)"
    )


def _find_hub(notif, hub_region):
    token = None
    while True:
        kwargs = {"maxResults": 3}
        if token:
            kwargs["nextToken"] = token
        resp = notif.list_notification_hubs(**kwargs)
        for hub in resp["notificationHubs"]:
            if hub["notificationHubRegion"] == hub_region:
                return hub
        token = resp.get("nextToken")
        if not token:
            return None


def _safe_deregister(notif, hub_region):
    try:
        notif.deregister_notification_hub(notificationHubRegion=hub_region)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

