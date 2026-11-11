"""list-outposts-includes-created-outpost."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-outposts-includes-created-outpost"
GROUP = "state"
SERVICES = ["outposts"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created Outpost's ID appears in the paginated ListOutposts results for the account."""
    outposts = ctx.client("outposts")
    site_id = outposts.create_site(
        Name=ctx.unique_name("sim2real-outposts-site-"),
        Tags={"sim2real-check": CHECK},
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=site_id))

    name = ctx.unique_name("sim2real-outposts-op-")
    outpost_id = outposts.create_outpost(
        Name=name,
        SiteId=site_id,
        AvailabilityZone=_pick_availability_zone(ctx),
        Tags={"sim2real-check": CHECK},
    )["Outpost"]["OutpostId"]
    ctx.on_cleanup(lambda: outposts.delete_outpost(OutpostId=outpost_id))

    found = _find_in_pages(outposts, "list_outposts", "Outposts", "OutpostId", outpost_id)
    assert found is not None, f"outpost {outpost_id} not found in ListOutposts"
    assert found["Name"] == name, f"expected Name {name!r}, got {found['Name']!r}"
    assert found["SiteId"] == site_id, f"expected SiteId {site_id!r}, got {found['SiteId']!r}"


def _pick_availability_zone(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert zones, "no available Availability Zones found in this region"
    return zones[0]["ZoneName"]


def _find_in_pages(client, method_name, items_key, id_key, target_id, max_pages=50):
    method = getattr(client, method_name)
    kwargs: dict = {}
    for _ in range(max_pages):
        resp = method(**kwargs)
        for item in resp.get(items_key, []):
            if item.get(id_key) == target_id:
                return item
        token = resp.get("NextToken")
        if not token:
            return None
        kwargs["NextToken"] = token
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
