"""device-reflects-site-assignment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "device-reflects-site-assignment"
GROUP = "state-machine"
SERVICES = ["networkmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDevice persists its SiteId/Type/Vendor, transitions to AVAILABLE, and DeleteDevice
    removes it for good."""
    nm = ctx.client("networkmanager")
    gn_id = _create_global_network(ctx, nm)
    site_id = _create_site(ctx, nm, gn_id)

    created = nm.create_device(
        GlobalNetworkId=gn_id,
        SiteId=site_id,
        Type="router",
        Vendor="Cisco",
        Model="ASR1001",
    )["Device"]
    device_id = created["DeviceId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_device(GlobalNetworkId=gn_id, DeviceId=device_id)))

    device = _poll_until(
        lambda: nm.get_devices(GlobalNetworkId=gn_id, DeviceIds=[device_id])["Devices"][0],
        lambda d: d["State"] == "AVAILABLE",
    )
    assert device["State"] == "AVAILABLE", f"expected State AVAILABLE, got {device['State']!r}"
    assert device["SiteId"] == site_id, f"expected SiteId {site_id!r}, got {device['SiteId']!r}"
    assert device["Type"] == "router", f"expected Type 'router', got {device['Type']!r}"
    assert device["Vendor"] == "Cisco", f"expected Vendor 'Cisco', got {device['Vendor']!r}"

    # Delete is already mandatory cleanup; prove it via an independent read and a second
    # mutation, rather than leaving it unasserted.
    nm.delete_device(GlobalNetworkId=gn_id, DeviceId=device_id)
    gone_states = _poll_until(
        lambda: _device_states(nm, gn_id, device_id),
        lambda states: states == [],
        timeout_s=40.0,
    )
    assert gone_states == [], f"expected device gone, last states {gone_states!r}"
    redelete_code, redelete_message = _error_code(lambda: nm.delete_device(GlobalNetworkId=gn_id, DeviceId=device_id))
    assert redelete_code == "ResourceNotFoundException", f"expected re-delete to fail not-found, got {redelete_code!r}"
    expected_message = "Resource not found."
    assert redelete_message == expected_message, f"expected message {expected_message!r}, got {redelete_message!r}"


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


def _device_states(nm, gn_id, device_id):
    """The states GetDevices reports for device_id, [] once it is gone: AWS answers a deleted id
    with either an empty list or ResourceNotFoundException 'Resource not found.'."""
    try:
        devices = nm.get_devices(GlobalNetworkId=gn_id, DeviceIds=[device_id])["Devices"]
    except ClientError as e:
        error = e.response["Error"]
        if error["Code"] == "ResourceNotFoundException" and error.get("Message") == "Resource not found.":
            return []
        raise
    return [d["State"] for d in devices]


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
