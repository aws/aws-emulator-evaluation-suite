"""associate-link-duplicate-is-an-idempotent-no-op."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-link-duplicate-is-an-idempotent-no-op"
GROUP = "state-machine"
SERVICES = ["networkmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateLink is idempotent for a repeated identical device+link pair: the second call
    succeeds (no ConflictException) and creates no duplicate association, while a different
    link for the same device creates a separate association."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    site_id = _create_site(ctx, nm, gn_id)
    device_id = _create_device(ctx, nm, gn_id, site_id)
    link_id = _create_link(ctx, nm, gn_id, site_id)

    nm.associate_link(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)
    ctx.on_cleanup(
        lambda: _safe_call(lambda: nm.disassociate_link(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id))
    )
    _poll_until(
        lambda: nm.get_link_associations(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)[
            "LinkAssociations"
        ][0]["LinkAssociationState"],
        lambda s: s == "AVAILABLE",
    )

    # Repeat: associating the identical device+link pair again does not error.
    repeat = nm.associate_link(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)["LinkAssociation"]
    assert repeat["DeviceId"] == device_id, f"actual: {repeat!r}"
    assert repeat["LinkId"] == link_id, f"actual: {repeat!r}"

    # Effect: exactly one association exists for this device+link pair, still AVAILABLE — no duplicate.
    associations = nm.get_link_associations(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link_id)[
        "LinkAssociations"
    ]
    assert len(associations) == 1, f"expected exactly one association, got {associations!r}"
    assert associations[0]["LinkAssociationState"] == "AVAILABLE", f"actual state: {associations[0]!r}"

    # Positive control: associating the same device with a DIFFERENT link creates a genuinely
    # separate association — proves the repeat above was idempotency, not a device-wide no-op.
    link2_id = _create_link(ctx, nm, gn_id, site_id)
    nm.associate_link(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link2_id)
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: nm.disassociate_link(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link2_id)
        )
    )
    state2 = _poll_until(
        lambda: nm.get_link_associations(GlobalNetworkId=gn_id, DeviceId=device_id, LinkId=link2_id)[
            "LinkAssociations"
        ][0]["LinkAssociationState"],
        lambda s: s == "AVAILABLE",
    )
    assert state2 == "AVAILABLE", f"actual state: {state2!r}"

    # Independent read at the destination: the device now has exactly the two distinct
    # associations (original link + the new one) — the repeat truly added nothing.
    all_assocs = nm.get_link_associations(GlobalNetworkId=gn_id, DeviceId=device_id)["LinkAssociations"]
    assert len(all_assocs) == 2, f"actual associations: {all_assocs!r}"
    assert {a["LinkId"] for a in all_assocs} == {link_id, link2_id}, f"actual associations: {all_assocs!r}"


# ===== helpers =====

def _safe_call(fn, timeout_s=60.0):
    """Teardown call: a missing resource is already gone; ConflictException (a dependent still
    being released) is retried every 2 s to the deadline; any other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["GlobalNetwork"]["GlobalNetworkId"]
    ctx.on_cleanup(lambda: _delete_global_network_and_wait(nm, gn_id))
    _poll_until(
        lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return gn_id


def _delete_global_network_and_wait(nm, gn_id):
    _safe_call(lambda: nm.delete_global_network(GlobalNetworkId=gn_id))
    # DescribeGlobalNetworks answers a deleted id with an empty list, not an error.
    _poll_until(
        lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"],
        lambda found: found == [],
        timeout_s=150.0,
        interval_s=2.0,
    )


def _create_site(ctx, nm, gn_id):
    site_id = nm.create_site(
        GlobalNetworkId=gn_id,
        Description=ctx.unique_name("sim2real-site-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_site(GlobalNetworkId=gn_id, SiteId=site_id)))
    _poll_until(
        lambda: nm.get_sites(GlobalNetworkId=gn_id, SiteIds=[site_id])["Sites"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return site_id


def _create_device(ctx, nm, gn_id, site_id):
    device_id = nm.create_device(
        GlobalNetworkId=gn_id, SiteId=site_id, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
