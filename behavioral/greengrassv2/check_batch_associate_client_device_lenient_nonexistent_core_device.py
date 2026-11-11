"""batch-associate-client-device-lenient-nonexistent-core-device."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-associate-client-device-lenient-nonexistent-core-device"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchAssociateClientDeviceWithCoreDevice for a thing never registered as a core device
    succeeds with empty errorEntries, and ListClientDevicesAssociatedWithCoreDevice then lists
    the client device.
    """
    gg = ctx.client("greengrassv2")
    core_device_name = ctx.unique_name("sim2real-ggv2-missing-core-")
    client_device_name = ctx.unique_name("sim2real-ggv2-client-")
    ctx.on_cleanup(
        lambda: _disassociate_ignore_errors(gg, core_device_name, client_device_name)
    )

    code, resp = _error_code_or_response(
        lambda: gg.batch_associate_client_device_with_core_device(
            coreDeviceThingName=core_device_name,
            entries=[{"thingName": client_device_name}],
        )
    )
    assert code is None, f"expected a successful (non-raising) response, got code={code!r}"
    error_entries = resp["errorEntries"]
    assert error_entries == [], (
        f"expected the association to succeed leniently (no core-device existence check "
        f"at request time), got error_entries={error_entries!r}"
    )

    associated = _poll_until(
        lambda: gg.list_client_devices_associated_with_core_device(
            coreDeviceThingName=core_device_name
        )["associatedClientDevices"],
        lambda devices: any(d["thingName"] == client_device_name for d in devices),
        timeout_s=30,
        interval_s=2,
    )
    assert len(associated) == 1, (
        f"expected exactly the one client device we associated, got {associated!r}"
    )
    assert associated[0]["thingName"] == client_device_name, (
        f"expected the associated device to be {client_device_name!r}, got {associated[0]!r}"
    )


def _error_code_or_response(fn):
    try:
        resp = fn()
        return None, resp
    except ClientError as e:
        return e.response["Error"]["Code"], None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _disassociate_ignore_errors(gg, core_device_name: str, client_device_name: str) -> None:
    try:
        gg.batch_disassociate_client_device_from_core_device(
            coreDeviceThingName=core_device_name,
            entries=[{"thingName": client_device_name}],
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

