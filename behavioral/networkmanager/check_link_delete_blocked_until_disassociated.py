"""link-delete-blocked-until-disassociated."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "link-delete-blocked-until-disassociated"
GROUP = "state-machine"
SERVICES = ["networkmanager"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLink is rejected while a device association exists, and succeeds once removed."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    site_id = _create_site(ctx, nm, gn_id)
    device_id = _create_device(ctx, nm, gn_id, site_id)
    link_id = _create_link(ctx, nm, gn_id, site_id)

    nm.associate_link(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)
    _poll_until(
        lambda: nm.get_link_associations(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)[
            "LinkAssociations"
        ][0]["LinkAssociationState"],
        lambda s: s == "AVAILABLE",
    )

    # Break: deleting a link that still has a device association must be rejected.
    code, message = _error_code(lambda: nm.delete_link(GlobalNetworkId=gn_id, LinkId=link_id))
    assert code == "ValidationException", f"expected ValidationException deleting an associated link, got {code!r}"
    expected_message = f"Link with ID {link_id} cannot be deleted due to existing association."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the link is still present and AVAILABLE, not DELETING.
    still_there = nm.get_links(GlobalNetworkId=gn_id, LinkIds=[link_id])["Links"][0]
    assert still_there["State"] == "AVAILABLE", f"expected link to remain AVAILABLE, got {still_there['State']!r}"

    # Positive control: after removing the association, deletion succeeds.
    nm.disassociate_link(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)
    _poll_until(
        lambda: nm.get_link_associations(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)[
            "LinkAssociations"
        ],
        lambda associations: len(associations) == 0,
        timeout_s=90.0,
    )
    nm.delete_link(GlobalNetworkId=gn_id, LinkId=link_id)
    remaining_links = _poll_until(
        lambda: nm.get_links(GlobalNetworkId=gn_id, LinkIds=[link_id])["Links"],
        lambda links: links == [],
        timeout_s=90.0,
    )
    assert remaining_links == [], (
        f"expected GetLinks to drop a deleted link from its filtered result, got {remaining_links!r}"
    )

    # Mutation on the dead id also fails: the link is gone, not merely absent from GetLinks.
    dead_code, dead_message = _error_code(
        lambda: nm.associate_link(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)
    )
    assert dead_code == "ValidationException", (
        f"expected ValidationException associating a deleted link, got {dead_code!r}"
    )
    expected_dead_message = "Link not found."
    assert dead_message == expected_dead_message, f"expected message {expected_dead_message!r}, got {dead_message!r}"


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
