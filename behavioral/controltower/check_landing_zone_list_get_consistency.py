"""landing-zone-list-get-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "landing-zone-list-get-consistency"
GROUP = "state"
SERVICES = ["controltower"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListLandingZones is a strict singleton view (at most one entry, by design), and
    whatever it returns is consistent with GetLandingZone: same ARN, and a status that is
    one of the documented LandingZoneStatus enum values."""
    ct = ctx.client("controltower")
    listed = ct.list_landing_zones()["landingZones"]
    assert len(listed) <= 1, f"ListLandingZones must return at most one entry, got {len(listed)}"

    if not listed:
        return  # no landing zone provisioned in this account/region; nothing further to cross-check

    summary = listed[0]
    detail = ct.get_landing_zone(landingZoneIdentifier=summary["arn"])["landingZone"]
    assert detail["arn"] == summary["arn"], (
        f"GetLandingZone arn {detail['arn']!r} does not match the ListLandingZones "
        f"entry it was looked up by, {summary['arn']!r}"
    )
    assert detail["status"] in ("ACTIVE", "PROCESSING", "FAILED"), (
        f"GetLandingZone returned status {detail['status']!r}, which is not one of the "
        f"documented LandingZoneStatus values (ACTIVE, PROCESSING, FAILED)"
    )
    assert isinstance(detail["manifest"], dict), (
        f"GetLandingZone manifest must be a JSON object, got {type(detail['manifest']).__name__}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
