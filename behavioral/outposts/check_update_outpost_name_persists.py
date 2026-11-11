"""update-outpost-name-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-outpost-name-persists"
GROUP = "state"
SERVICES = ["outposts"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateOutpost changes Name/Description/SupportedHardwareType and GetOutpost reflects it."""
    outposts = ctx.client("outposts")
    site_id = outposts.create_site(
        Name=ctx.unique_name("sim2real-outposts-site-"),
        Tags={"sim2real-check": CHECK},
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=site_id))

    outpost_id = outposts.create_outpost(
        Name=ctx.unique_name("sim2real-outposts-op-"),
        SiteId=site_id,
        SupportedHardwareType="RACK",
        AvailabilityZone=_pick_availability_zone(ctx),
        Tags={"sim2real-check": CHECK},
    )["Outpost"]["OutpostId"]
    ctx.on_cleanup(lambda: outposts.delete_outpost(OutpostId=outpost_id))

    new_name = ctx.unique_name("sim2real-outposts-op-renamed-")
    outposts.update_outpost(
        OutpostId=outpost_id,
        Name=new_name,
        Description="renamed by behavioral check",
        SupportedHardwareType="SERVER",
    )

    got = outposts.get_outpost(OutpostId=outpost_id)["Outpost"]
    assert got["Name"] == new_name, f"expected Name {new_name!r}, got {got['Name']!r}"
    assert got["Description"] == "renamed by behavioral check", (
        f"expected Description 'renamed by behavioral check', got {got['Description']!r}"
    )
    assert got["SupportedHardwareType"] == "SERVER", (
        f"expected SupportedHardwareType 'SERVER', got {got['SupportedHardwareType']!r}"
    )


def _pick_availability_zone(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert zones, "no available Availability Zones found in this region"
    return zones[0]["ZoneName"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
