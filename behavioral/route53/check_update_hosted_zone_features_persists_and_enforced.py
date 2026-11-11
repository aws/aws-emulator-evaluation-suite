"""update-hosted-zone-features-persists-and-enforced."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "update-hosted-zone-features-persists-and-enforced"
GROUP = "server-side"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A feature enabled via UpdateHostedZoneFeatures (accelerated recovery) persists on
    the zone and is visible on subsequent GetHostedZone reads, reaching ENABLED."""
    r53 = ctx.client("route53")

    zone_resp = r53.create_hosted_zone(
        Name=f"{ctx.unique_name('sim2reals-r53-')}.com.",
        CallerReference=str(uuid.uuid4()),
    )
    zone_id = zone_resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: r53.delete_hosted_zone(Id=zone_id))

    # Before enabling, the feature must not already be reported as enabled.
    before = r53.get_hosted_zone(Id=zone_id)["HostedZone"].get("Features", {})
    before_status = before.get("AcceleratedRecoveryStatus")
    assert before_status in (None, "DISABLED"), before_status

    r53.update_hosted_zone_features(HostedZoneId=zone_id, EnableAcceleratedRecovery=True)

    status = _poll_accelerated_recovery_status(
        r53, zone_id, {"ENABLED"}, terminal_failures={"ENABLE_FAILED"}, timeout_s=420.0, interval_s=10.0
    )
    assert status == "ENABLED", status

    # A second, independent GetHostedZone read still shows the persisted feature.
    again = r53.get_hosted_zone(Id=zone_id)["HostedZone"]["Features"]["AcceleratedRecoveryStatus"]
    assert again == "ENABLED", again


def _poll_accelerated_recovery_status(r53, zone_id, terminal_ok, terminal_failures, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        features = r53.get_hosted_zone(Id=zone_id)["HostedZone"].get("Features", {})
        status = features.get("AcceleratedRecoveryStatus")
        if status in terminal_ok or status in terminal_failures:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"AcceleratedRecoveryStatus never reached a terminal state, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
