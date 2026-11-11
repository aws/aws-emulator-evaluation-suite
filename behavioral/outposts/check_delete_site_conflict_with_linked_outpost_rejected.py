"""delete-site-conflict-with-linked-outpost-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-site-conflict-with-linked-outpost-rejected"
GROUP = "overly-permissive"
SERVICES = ["outposts"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSite on a site with a linked Outpost fails with ValidationException and the message "Site <id> cannot
    be deleted because it has one or more outposts." and the site stays readable; after DeleteOutpost the same
    call succeeds and GetSite fails with NotFoundException, as it does for a site with no Outpost.
    """
    outposts = ctx.client("outposts")

    # Positive control: a Site with no linked Outpost deletes immediately.
    baseline_site_id = outposts.create_site(
        Name=ctx.unique_name("sim2real-outposts-site-baseline-")
    )["Site"]["SiteId"]
    outposts.delete_site(SiteId=baseline_site_id)
    code, message = _error(lambda: outposts.get_site(SiteId=baseline_site_id))
    assert code == "NotFoundException", f"expected NotFoundException for the deleted baseline Site, got {code}"
    assert message == f"siteId={baseline_site_id}", f"unexpected GetSite message: {message!r}"

    # Break exactly one thing: link an Outpost to a fresh Site.
    site_id = outposts.create_site(Name=ctx.unique_name("sim2real-outposts-site-"))["Site"]["SiteId"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(lambda: outposts.delete_site(SiteId=site_id)))
    az = _pick_availability_zone(ctx)
    outpost_id = outposts.create_outpost(
        Name=ctx.unique_name("sim2real-outposts-op-"),
        SiteId=site_id,
        AvailabilityZone=az,
    )["Outpost"]["OutpostId"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(lambda: outposts.delete_outpost(OutpostId=outpost_id)))

    # The specific error, with the linked Outpost still present.
    code, message = _error(lambda: outposts.delete_site(SiteId=site_id))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == f"Site {site_id} cannot be deleted because it has one or more outposts.", (
        f"unexpected DeleteSite refusal message: {message!r}"
    )

    # Effect absent: an independent read shows the Site survives the rejected delete.
    survived = outposts.get_site(SiteId=site_id)["Site"]
    assert survived["SiteId"] == site_id, "Site should still be readable after the rejected delete"

    # Restore: remove the dependent Outpost.
    outposts.delete_outpost(OutpostId=outpost_id)
    code, message = _error(lambda: outposts.get_outpost(OutpostId=outpost_id))
    assert code == "NotFoundException", f"expected NotFoundException for the deleted Outpost, got {code}"
    assert message == f"outpostId={outpost_id}", f"unexpected GetOutpost message: {message!r}"

    # The identical DeleteSite call then succeeds.
    outposts.delete_site(SiteId=site_id)
    code, message = _error(lambda: outposts.get_site(SiteId=site_id))
    assert code == "NotFoundException", (
        f"Site should be gone once its only linked Outpost is removed, got {code}"
    )
    assert message == f"siteId={site_id}", f"unexpected GetSite message: {message!r}"


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
