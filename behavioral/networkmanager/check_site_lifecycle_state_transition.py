"""site-lifecycle-state-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "site-lifecycle-state-transition"
GROUP = "state-machine"
SERVICES = ["networkmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSite transitions to AVAILABLE, persists Location, and DeleteSite makes it gone."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)

    location = {"Address": "123 Main St", "Latitude": "47.6062", "Longitude": "-122.3321"}
    created = nm.create_site(
        GlobalNetworkId=gn_id,
        Description=ctx.unique_name("sim2real-site-"),
        Location=location,
        Tags=[{"Key": "sim2real-team", "Value": "net-eng"}],
    )["Site"]
    site_id = created["SiteId"]
    site_arn = created["SiteArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_site(GlobalNetworkId=gn_id, SiteId=site_id)))
    assert created["State"] in ("PENDING", "AVAILABLE"), (
        f"expected CreateSite response State in (PENDING, AVAILABLE), got {created['State']!r}"
    )

    _poll_until(
        lambda: nm.get_sites(GlobalNetworkId=gn_id, SiteIds=[site_id])["Sites"][0],
        lambda s: s["State"] == "AVAILABLE",
    )
    # Independent read, issued after the polling loop already observed AVAILABLE: proves the
    # state is stable and re-observable, not an artifact of the one call that satisfied the poll.
    site = nm.get_sites(GlobalNetworkId=gn_id, SiteIds=[site_id])["Sites"][0]
    assert site["State"] == "AVAILABLE", f"expected AVAILABLE on re-read, got {site['State']!r}"
    assert site["Location"]["Address"] == "123 Main St", (
        f"expected Location.Address '123 Main St', got {site['Location'].get('Address')!r}"
    )
    assert site["Location"]["Latitude"] == "47.6062", (
        f"expected Location.Latitude '47.6062', got {site['Location'].get('Latitude')!r}"
    )
    assert site["Location"]["Longitude"] == "-122.3321", (
        f"expected Location.Longitude '-122.3321', got {site['Location'].get('Longitude')!r}"
    )

    nm.delete_site(GlobalNetworkId=gn_id, SiteId=site_id)
    deleted_code = _poll_until(
        lambda: _site_read_after_delete(nm, gn_id, site_id),
        lambda c: c == "GONE",
        timeout_s=150.0,
    )
    assert deleted_code == "GONE", (
        f"expected the site to become unreadable after delete, got {deleted_code!r}"
    )
    tag_err, tag_message = _error_code(
        lambda: nm.tag_resource(ResourceArn=site_arn, Tags=[{"Key": "probe", "Value": "post-delete"}])
    )
    assert tag_err == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException tagging a deleted site, got {tag_err!r}"
    )
    expected_message = "Resource not found."
    assert tag_message == expected_message, f"expected message {expected_message!r}, got {tag_message!r}"


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


def _site_read_after_delete(nm, gn_id, site_id):
    """"GONE" once GetSites either 404s or drops the id from its own by-id filter; else the raw state."""
    try:
        sites = nm.get_sites(GlobalNetworkId=gn_id, SiteIds=[site_id])["Sites"]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        return "GONE" if code == "ResourceNotFoundException" else code
    return "GONE" if not sites else sites[0]["State"]


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
