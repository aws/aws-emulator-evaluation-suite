"""link-reflects-bandwidth-configuration."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "link-reflects-bandwidth-configuration"
GROUP = "state-machine"
SERVICES = ["networkmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLink persists the exact Bandwidth values and transitions to AVAILABLE."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    site_id = _create_site(ctx, nm, gn_id)

    created = nm.create_link(
        GlobalNetworkId=gn_id,
        SiteId=site_id,
        Bandwidth={"UploadSpeed": 10, "DownloadSpeed": 50},
        Provider="sim2real-isp",
        Type="broadband",
        Tags=[{"Key": "sim2real-team", "Value": "net-eng"}],
    )["Link"]
    link_id = created["LinkId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_link(GlobalNetworkId=gn_id, LinkId=link_id)))

    link = _poll_until(
        lambda: nm.get_links(GlobalNetworkId=gn_id, LinkIds=[link_id])["Links"][0],
        lambda candidate_link: candidate_link["State"] == "AVAILABLE",
    )
    assert link["State"] == "AVAILABLE", f"expected State=AVAILABLE, got {link['State']!r}"
    assert link["Bandwidth"]["UploadSpeed"] == 10, (
        f"expected Bandwidth.UploadSpeed=10, got {link['Bandwidth'].get('UploadSpeed')!r}"
    )
    assert link["Bandwidth"]["DownloadSpeed"] == 50, (
        f"expected Bandwidth.DownloadSpeed=50, got {link['Bandwidth'].get('DownloadSpeed')!r}"
    )
    assert link["Provider"] == "sim2real-isp", f"expected Provider='sim2real-isp', got {link.get('Provider')!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
