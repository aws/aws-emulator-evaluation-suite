"""update-site-rack-physical-properties-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-site-rack-physical-properties-persists"
GROUP = "state"
SERVICES = ["outposts"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSiteRackPhysicalProperties changes rack power/uplink specs and GetSite reflects them."""
    outposts = ctx.client("outposts")
    site_id = outposts.create_site(
        Name=ctx.unique_name("sim2real-outposts-site-"),
        Tags={"sim2real-check": CHECK},
        RackPhysicalProperties={
            "PowerDrawKva": "POWER_5_KVA",
            "PowerPhase": "SINGLE_PHASE",
            "PowerConnector": "L6_30P",
            "PowerFeedDrop": "ABOVE_RACK",
            "UplinkGbps": "UPLINK_1G",
            "UplinkCount": "UPLINK_COUNT_1",
        },
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(lambda: outposts.delete_site(SiteId=site_id)))

    outposts.update_site_rack_physical_properties(
        SiteId=site_id,
        PowerDrawKva="POWER_30_KVA",
        PowerPhase="THREE_PHASE",
        PowerConnector="CS8365C",
        PowerFeedDrop="BELOW_RACK",
        UplinkGbps="UPLINK_10G",
        UplinkCount="UPLINK_COUNT_2",
        FiberOpticCableType="MULTI_MODE",
        OpticalStandard="OPTIC_10GBASE_SR",
        MaximumSupportedWeightLbs="MAX_2000_LBS",
    )

    rack = outposts.get_site(SiteId=site_id)["Site"]["RackPhysicalProperties"]
    assert rack["PowerDrawKva"] == "POWER_30_KVA", f"expected POWER_30_KVA, got {rack.get('PowerDrawKva')}"
    assert rack["PowerPhase"] == "THREE_PHASE", f"expected THREE_PHASE, got {rack.get('PowerPhase')}"
    assert rack["PowerConnector"] == "CS8365C", f"expected CS8365C, got {rack.get('PowerConnector')}"
    assert rack["PowerFeedDrop"] == "BELOW_RACK", f"expected BELOW_RACK, got {rack.get('PowerFeedDrop')}"
    assert rack["UplinkGbps"] == "UPLINK_10G", f"expected UPLINK_10G, got {rack.get('UplinkGbps')}"
    assert rack["UplinkCount"] == "UPLINK_COUNT_2", f"expected UPLINK_COUNT_2, got {rack.get('UplinkCount')}"
    assert rack["FiberOpticCableType"] == "MULTI_MODE", (
        f"expected MULTI_MODE, got {rack.get('FiberOpticCableType')}"
    )
    assert rack["OpticalStandard"] == "OPTIC_10GBASE_SR", (
        f"expected OPTIC_10GBASE_SR, got {rack.get('OpticalStandard')}"
    )
    assert rack["MaximumSupportedWeightLbs"] == "MAX_2000_LBS", (
        f"expected MAX_2000_LBS, got {rack.get('MaximumSupportedWeightLbs')}"
    )

    # Post-cleanup negative: the delete is already mandatory, so prove it took effect.
    outposts.delete_site(SiteId=site_id)
    not_found_code, message = _error(lambda: outposts.get_site(SiteId=site_id))
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException reading a deleted site, got {not_found_code}"
    )
    assert message == f"siteId={site_id}", f"unexpected GetSite message for a deleted site: {message!r}"


def _error(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_ignoring_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
