"""delete-site-blocked-until-device-removed."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-site-blocked-until-device-removed"
GROUP = "state-machine"
SERVICES = ["networkmanager"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSite is rejected while a device still references it, and succeeds once removed."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    site_id, site_arn = _create_site(ctx, nm, gn_id)
    device_id = nm.create_device(GlobalNetworkId=gn_id, SiteId=site_id)["Device"]["DeviceId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_device(GlobalNetworkId=gn_id, DeviceId=device_id)))
    _poll_until(
        lambda: nm.get_devices(GlobalNetworkId=gn_id, DeviceIds=[device_id])["Devices"][0]["State"],
        lambda s: s == "AVAILABLE",
    )

    # Break: deleting a site that still has a device is rejected.
    code, message = _error_code(lambda: nm.delete_site(GlobalNetworkId=gn_id, SiteId=site_id))
    assert code == "ValidationException", f"actual code: {code!r}"
    expected_message = f"Site with ID {site_id} cannot be deleted due to existing association."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the site is still present and AVAILABLE.
    still_there = nm.get_sites(GlobalNetworkId=gn_id, SiteIds=[site_id])["Sites"][0]
    assert still_there["State"] == "AVAILABLE"

    # Positive control: after removing the device, site deletion succeeds.
    nm.delete_device(GlobalNetworkId=gn_id, DeviceId=device_id)
    _poll_until(
        lambda: len(nm.get_devices(GlobalNetworkId=gn_id, DeviceIds=[device_id])["Devices"]),
        lambda n: n == 0,
        timeout_s=30.0,
    )
    nm.delete_site(GlobalNetworkId=gn_id, SiteId=site_id)
    remaining_sites = _poll_until(
        lambda: nm.get_sites(GlobalNetworkId=gn_id, SiteIds=[site_id])["Sites"],
        lambda sites: len(sites) == 0,
        timeout_s=30.0,
    )
    assert remaining_sites == [], f"actual: {remaining_sites!r}"

    # Dead id is unusable, not just absent from reads: a mutation against it fails too.
    mutate_code, mutate_message = _error_code(
        lambda: nm.tag_resource(ResourceArn=site_arn, Tags=[{"Key": "sim2real-post-delete", "Value": "x"}])
    )
    assert mutate_code == "ResourceNotFoundException", f"actual code: {mutate_code!r}"
    expected_mutate_message = "Resource not found."
    assert mutate_message == expected_mutate_message, (
        f"expected message {expected_mutate_message!r}, got {mutate_message!r}"
    )


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
    site = nm.create_site(GlobalNetworkId=gn_id, Description=ctx.unique_name("sim2real-site-"))["Site"]
    site_id = site["SiteId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_site(GlobalNetworkId=gn_id, SiteId=site_id)))
    _poll_until(
        lambda: nm.get_sites(GlobalNetworkId=gn_id, SiteIds=[site_id])["Sites"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return site_id, site["SiteArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
