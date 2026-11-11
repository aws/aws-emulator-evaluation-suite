"""site-to-outpost-to-quote-e2e-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "site-to-outpost-to-quote-e2e-lifecycle"
GROUP = "e2e"
SERVICES = ["outposts"]
_UNIT = "c5.24xlarge"  # large-instance: a quote prices Outposts capacity and launches nothing


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A site, an Outpost registered to it and a quote for that Outpost are reported with the same linked ids by
    GetSite, GetOutpost, GetQuote and ListOutposts; deleted in dependency order, each then fails with
    NotFoundException and its exact message.
    """
    outposts = ctx.client("outposts")

    # Step 1: create the Site.
    site_id = outposts.create_site(
        Name=ctx.unique_name("sim2real-outposts-site-"),
        Tags={"sim2real-check": CHECK},
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(lambda: outposts.delete_site(SiteId=site_id)))

    # Step 2: register an Outpost against that Site, in a real AZ.
    az = _pick_availability_zone(ctx)
    outpost_name = ctx.unique_name("sim2real-outposts-op-")
    created = outposts.create_outpost(
        Name=outpost_name,
        Description="behavioral fidelity test outpost",
        SiteId=site_id,
        SupportedHardwareType="RACK",
        AvailabilityZone=az,
        Tags={"sim2real-check": CHECK},
    )["Outpost"]
    outpost_id = created["OutpostId"]
    outpost_arn = created["OutpostArn"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(lambda: outposts.delete_outpost(OutpostId=outpost_id)))

    assert created["SiteId"] == site_id, f"expected SiteId {site_id}, got {created['SiteId']}"
    assert created["Name"] == outpost_name, f"expected Name {outpost_name}, got {created['Name']}"
    assert created["SupportedHardwareType"] == "RACK", (
        f"expected SupportedHardwareType RACK, got {created['SupportedHardwareType']}"
    )
    assert outpost_arn.endswith(f"outpost/{outpost_id}"), (
        f"expected OutpostArn to end with outpost/{outpost_id}, got {outpost_arn}"
    )

    got_outpost = outposts.get_outpost(OutpostId=outpost_id)["Outpost"]
    assert got_outpost["OutpostId"] == outpost_id, (
        f"expected OutpostId {outpost_id}, got {got_outpost['OutpostId']}"
    )
    assert got_outpost["SiteId"] == site_id, f"expected SiteId {site_id}, got {got_outpost['SiteId']}"
    assert got_outpost["Name"] == outpost_name, f"expected Name {outpost_name}, got {got_outpost['Name']}"
    assert isinstance(got_outpost["LifeCycleStatus"], str) and len(got_outpost["LifeCycleStatus"]) > 0, (
        f"expected a non-empty LifeCycleStatus string, got {got_outpost.get('LifeCycleStatus')!r}"
    )

    # Step 3: create a Quote associated with that Outpost.
    quote = outposts.create_quote(
        CountryCode="US",
        OutpostIdentifier=outpost_id,
        RequestedCapacities=[{"QuoteCapacityType": "EC2", "Unit": _UNIT, "Quantity": 4.0}],
    )["Quote"]
    quote_id = quote["QuoteId"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(lambda: outposts.delete_quote(QuoteIdentifier=quote_id)))
    assert quote["QuoteStatus"] == "CREATED", f"expected QuoteStatus CREATED, got {quote['QuoteStatus']}"

    # Cross-check: every read path agrees on the linkage.
    got_site = outposts.get_site(SiteId=site_id)["Site"]
    assert got_site["SiteId"] == site_id, f"expected SiteId {site_id}, got {got_site['SiteId']}"

    got_quote = outposts.get_quote(QuoteIdentifier=quote_id)["Quote"]
    assert got_quote["QuoteId"] == quote_id, f"expected QuoteId {quote_id}, got {got_quote['QuoteId']}"
    assert got_quote["QuoteStatus"] == "CREATED", (
        f"expected QuoteStatus CREATED, got {got_quote['QuoteStatus']}"
    )
    assert got_quote["RequestedCapacities"][0]["Unit"] == _UNIT, (
        f"expected Unit {_UNIT}, got {got_quote['RequestedCapacities'][0]['Unit']}"
    )

    listed_outposts = outposts.list_outposts().get("Outposts", [])
    assert any(o["OutpostId"] == outpost_id and o["SiteId"] == site_id for o in listed_outposts), (
        f"expected outpost {outpost_id} linked to site {site_id} in ListOutposts, got {listed_outposts}"
    )

    # Step 4: tear down in dependency order and confirm each becomes unreachable.
    outposts.delete_quote(QuoteIdentifier=quote_id)
    code, message = _error(lambda: outposts.get_quote(QuoteIdentifier=quote_id))
    assert code == "NotFoundException", f"expected NotFoundException after DeleteQuote, got {code}"
    assert message == f"Could not find Quote with identifier {quote_id}", (
        f"unexpected GetQuote message after DeleteQuote: {message!r}"
    )

    outposts.delete_outpost(OutpostId=outpost_id)
    code, message = _error(lambda: outposts.get_outpost(OutpostId=outpost_id))
    assert code == "NotFoundException", f"expected NotFoundException after DeleteOutpost, got {code}"
    assert message == f"outpostId={outpost_id}", f"unexpected GetOutpost message after DeleteOutpost: {message!r}"

    outposts.delete_site(SiteId=site_id)
    code, message = _error(lambda: outposts.get_site(SiteId=site_id))
    assert code == "NotFoundException", f"expected NotFoundException after DeleteSite, got {code}"
    assert message == f"siteId={site_id}", f"unexpected GetSite message after DeleteSite: {message!r}"


def _pick_availability_zone(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert zones, "no available Availability Zones found in this region"
    return zones[0]["ZoneName"]


def _delete_ignoring_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
