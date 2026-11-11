"""get-network-resource-counts-reflects-resources."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-network-resource-counts-reflects-resources"
GROUP = "telemetry"
SERVICES = ["networkmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetNetworkResourceCounts aggregates site/device/link counts for a global network, and
    reflects a resource's removal as faithfully as it reflects its arrival."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    site_id = _create_site(ctx, nm, gn_id)
    _create_device(ctx, nm, gn_id, site_id)
    link_id = _create_link(ctx, nm, gn_id, site_id)

    counts = _poll_until(
        lambda: _counts(nm, gn_id),
        lambda c: c.get("site", 0) >= 1 and c.get("device", 0) >= 1 and c.get("link", 0) >= 1,
        timeout_s=90.0,
    )
    assert counts["site"] == 1, f"expected exactly 1 site counted, got {counts.get('site')}"
    assert counts["device"] == 1, f"expected exactly 1 device counted, got {counts.get('device')}"
    assert counts["link"] == 1, f"expected exactly 1 link counted, got {counts.get('link')}"

    # "Reflects resources" cuts both ways: prove the count drops back when the resource is
    # gone, not only that it rose when the resource arrived.
    nm.delete_link(GlobalNetworkId=gn_id, LinkId=link_id)
    after = _poll_until(
        lambda: _counts(nm, gn_id),
        lambda c: c.get("link", 0) == 0,
        timeout_s=90.0,
    )
    assert after.get("link", 0) == 0, f"expected link count 0 after delete, got {after.get('link')}"
    assert after["site"] == 1, f"expected site count unchanged at 1, got {after.get('site')}"
    assert after["device"] == 1, f"expected device count unchanged at 1, got {after.get('device')}"


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


def _counts(nm, gn_id):
    return {
        e["ResourceType"]: e["Count"]
        for e in nm.get_network_resource_counts(GlobalNetworkId=gn_id)["NetworkResourceCounts"]
    }


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
    gn_id = nm.create_global_network(Description=ctx.unique_name("sim2real-gn-"))["GlobalNetwork"]["GlobalNetworkId"]
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
    site_id = nm.create_site(GlobalNetworkId=gn_id, Description=ctx.unique_name("sim2real-site-"))["Site"]["SiteId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_site(GlobalNetworkId=gn_id, SiteId=site_id)))
    _poll_until(
        lambda: nm.get_sites(GlobalNetworkId=gn_id, SiteIds=[site_id])["Sites"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return site_id


def _create_device(ctx, nm, gn_id, site_id):
    device_id = nm.create_device(GlobalNetworkId=gn_id, SiteId=site_id)["Device"]["DeviceId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_device(GlobalNetworkId=gn_id, DeviceId=device_id)))
    _poll_until(
        lambda: nm.get_devices(GlobalNetworkId=gn_id, DeviceIds=[device_id])["Devices"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return device_id


def _create_link(ctx, nm, gn_id, site_id):
    link_id = nm.create_link(
        GlobalNetworkId=gn_id, SiteId=site_id, Bandwidth={"UploadSpeed": 10, "DownloadSpeed": 10}
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
