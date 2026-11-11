"""create-connection-cross-global-network-device-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-connection-cross-global-network-device-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmanager"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConnection rejects a ConnectedDeviceId that belongs to a different global network."""
    nm = ctx.client("networkmanager")
    gn1_id = _create_global_network(ctx, nm)
    gn2_id = _create_global_network(ctx, nm)
    device_a = _create_device(ctx, nm, gn1_id)
    device_foreign = _create_device(ctx, nm, gn2_id)

    # Break: device_foreign belongs to gn2, not gn1 -- it is not visible from gn1's namespace.
    code, message = _error_code(
        lambda: nm.create_connection(
            GlobalNetworkId=gn1_id, DeviceId=device_a, ConnectedDeviceId=device_foreign
        )
    )
    assert code == "ValidationException", f"actual code: {code!r}"
    expected_message = "Device not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no connection was created in either global network.
    gn1_connections = nm.get_connections(GlobalNetworkId=gn1_id)["Connections"]
    assert gn1_connections == [], f"expected no connections in gn1, got: {gn1_connections!r}"
    gn2_connections = nm.get_connections(GlobalNetworkId=gn2_id)["Connections"]
    assert gn2_connections == [], f"expected no connections in gn2, got: {gn2_connections!r}"

    # Positive control: connecting two devices that both belong to gn1 succeeds.
    device_b = _create_device(ctx, nm, gn1_id)
    created = nm.create_connection(GlobalNetworkId=gn1_id, DeviceId=device_a, ConnectedDeviceId=device_b)[
        "Connection"
    ]
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: nm.delete_connection(GlobalNetworkId=gn1_id, ConnectionId=created["ConnectionId"])
        )
    )
    assert created["State"] in ("PENDING", "AVAILABLE"), f"actual state: {created['State']!r}"

    # Terminal read: an independent operation (not create_connection's own response) confirms
    # the connection exists in gn1's namespace.
    gn1_connections_after = nm.get_connections(GlobalNetworkId=gn1_id)["Connections"]
    assert any(c["ConnectionId"] == created["ConnectionId"] for c in gn1_connections_after), (
        f"expected {created['ConnectionId']!r} in gn1 connections, got: {gn1_connections_after!r}"
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


def _create_device(ctx, nm, gn_id):
    device_id = nm.create_device(GlobalNetworkId=gn_id)["Device"]["DeviceId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: nm.delete_device(GlobalNetworkId=gn_id, DeviceId=device_id)))
    _poll_until(
        lambda: nm.get_devices(GlobalNetworkId=gn_id, DeviceIds=[device_id])["Devices"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return device_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
