"""associate-link-state-transition-and-listing."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-link-state-transition-and-listing"
GROUP = "state-machine"
SERVICES = ["networkmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateLink transitions to AVAILABLE and appears in GetLinkAssociations; disassociating removes it."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    site_id = _create_site(ctx, nm, gn_id)
    device_id = _create_device(ctx, nm, gn_id, site_id)
    link_id = _create_link(ctx, nm, gn_id, site_id)

    assoc = nm.associate_link(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)["LinkAssociation"]
    assert assoc["LinkAssociationState"] in ("PENDING", "AVAILABLE"), (
        f"expected AssociateLink to report PENDING or AVAILABLE, got {assoc['LinkAssociationState']!r}"
    )

    def _cleanup_assoc():
        try:
            nm.disassociate_link(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_assoc)

    state = _poll_until(
        lambda: nm.get_link_associations(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)[
            "LinkAssociations"
        ][0]["LinkAssociationState"],
        lambda s: s == "AVAILABLE",
    )
    assert state == "AVAILABLE", f"expected GetLinkAssociations to reach AVAILABLE, last seen {state!r}"

    nm.disassociate_link(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)

    empty = _poll_until(
        lambda: nm.get_link_associations(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)[
            "LinkAssociations"
        ],
        lambda associations: len(associations) == 0,
        timeout_s=90.0,
    )
    assert empty == [], f"expected GetLinkAssociations to list no associations after DisassociateLink, got {empty!r}"


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _is_gone(fn):
    """True once fn() is refused with ResourceNotFoundException or answers an empty list (polling only)."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"] == "ResourceNotFoundException"
    return result == []


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_global_network(ctx, nm):
    gn_id = nm.create_global_network(
        Description=ctx.unique_name("sim2real-gn-"),
        Tags=[{"Key": "sim2real-team", "Value": "net-eng"}],
    )["GlobalNetwork"]["GlobalNetworkId"]
    ctx.on_cleanup(lambda: _delete_global_network_and_wait(nm, gn_id))
    _poll_until(
        lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return gn_id


def _delete_global_network_and_wait(nm, gn_id):
    _safe_call(lambda: nm.delete_global_network(GlobalNetworkId=gn_id))
    _poll_until(
        lambda: _is_gone(lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"]),
        lambda gone: gone,
        timeout_s=150.0,
    )


def _create_site(ctx, nm, gn_id):
    site_id = nm.create_site(
        GlobalNetworkId=gn_id,
        Description=ctx.unique_name("sim2real-site-"),
        Tags=[{"Key": "sim2real-team", "Value": "net-eng"}],
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_site(GlobalNetworkId=gn_id, SiteId=site_id)))
    _poll_until(
        lambda: nm.get_sites(GlobalNetworkId=gn_id, SiteIds=[site_id])["Sites"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return site_id


def _create_device(ctx, nm, gn_id, site_id):
    device_id = nm.create_device(
        GlobalNetworkId=gn_id,
        SiteId=site_id,
        Tags=[{"Key": "sim2real-team", "Value": "net-eng"}],
    )["Device"]["DeviceId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_device(GlobalNetworkId=gn_id, DeviceId=device_id)))
    _poll_until(
        lambda: nm.get_devices(GlobalNetworkId=gn_id, DeviceIds=[device_id])["Devices"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return device_id


def _create_link(ctx, nm, gn_id, site_id):
    link_id = nm.create_link(
        GlobalNetworkId=gn_id,
        SiteId=site_id,
        Bandwidth={"UploadSpeed": 10, "DownloadSpeed": 10},
        Tags=[{"Key": "sim2real-team", "Value": "net-eng"}],
    )["Link"]["LinkId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_link(GlobalNetworkId=gn_id, LinkId=link_id)))
    _poll_until(
        lambda: nm.get_links(GlobalNetworkId=gn_id, LinkIds=[link_id])["Links"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return link_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
