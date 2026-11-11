"""decommission-rejected-for-non-active-lifecycle-status."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "decommission-rejected-for-non-active-lifecycle-status"
GROUP = "state"
SERVICES = ["outposts"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartOutpostDecommission with ValidateOnly on an Outpost that never reached ACTIVE fails with
    ValidationException and the message "Outpost <id> has invalid lifecycleStatus=<status>", and GetOutpost
    still returns the Outpost with the same status.
    """
    outposts = ctx.client("outposts")
    site_id = outposts.create_site(
        Name=ctx.unique_name("sim2real-outposts-site-"),
        Tags={"sim2real-check": CHECK},
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=site_id))

    outpost_id = outposts.create_outpost(
        Name=ctx.unique_name("sim2real-outposts-op-"),
        SiteId=site_id,
        AvailabilityZone=_pick_availability_zone(ctx),
        Tags={"sim2real-check": CHECK},
    )["Outpost"]["OutpostId"]
    ctx.on_cleanup(lambda: outposts.delete_outpost(OutpostId=outpost_id))

    # A freshly registered Outpost never reaches ACTIVE (no hardware was ever installed).
    before = outposts.get_outpost(OutpostId=outpost_id)["Outpost"]
    status = before["LifeCycleStatus"]
    assert status != "ACTIVE", f"expected a non-ACTIVE lifecycle status, got {status!r}"

    code, message = _error_code(
        lambda: outposts.start_outpost_decommission(OutpostIdentifier=outpost_id, ValidateOnly=True)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r} ({message!r})"
    # The message names the offending status itself -- tie it to what GetOutpost just reported,
    # not to a guessed literal such as PENDING.
    expected = f"Outpost {outpost_id} has invalid lifecycleStatus={status}"
    assert message == expected, (
        f"expected the ValidationException message {expected!r}, got message={message!r}"
    )

    # The Outpost itself is unaffected by the rejected decommission attempt.
    got = outposts.get_outpost(OutpostId=outpost_id)["Outpost"]
    assert got["OutpostId"] == outpost_id, f"expected OutpostId {outpost_id!r}, got {got['OutpostId']!r}"
    assert got["LifeCycleStatus"] == status, (
        f"expected LifeCycleStatus to stay {status!r} after the rejected decommission, "
        f"got {got['LifeCycleStatus']!r}"
    )


def _pick_availability_zone(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert zones, "no available Availability Zones found in this region"
    return zones[0]["ZoneName"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected start_outpost_decommission to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
